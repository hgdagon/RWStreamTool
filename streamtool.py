#!/usr/bin/env python3

import json
from io import BytesIO
from mmap import mmap, ACCESS_READ
from pathlib import Path
from struct import pack, unpack
from dataclasses import dataclass, asdict, field
import sys
from uuid import UUID

@dataclass
class StreamChunk:
    id: str
    size: int
    version: int
    type: str = field(init=False)
    filename: str

    def __post_init__(self):
        self.type = type(self).__name__.removesuffix('Chunk').upper()


@dataclass
class CRDChunk(StreamChunk):
    data: dict


@dataclass
class CodeChunk(StreamChunk):
    data: bytes


@dataclass
class AssetChunk(StreamChunk):
    name: str
    guid: UUID
    asset_type: str
    source_path: str
    target_path: str
    separator: str  # `00 00 00 00` for most, but may be `FF FF FF FF` on GC (which exactly?)
    data: bytes | dict
    extra: None | str | dict | list[dict] = None

    def __post_init__(self):
        super().__post_init__()
        if self.size > 4206559400:
            # unk1 is 181-208 (0xB500-0xD000) on PSP and 181 (0xB500) elsewhere
            # unk2 is always 64187 (0xFABB)
            self.unk1, self.unk2 = unpack(f'<HH', pack('<I', self.size))


class RWStream:
    SERIALIZERS = {
        ('type', 'CRD'): '_serialize_crd',
        ('asset_type', 'LOCXML'): '_serialize_locxml',
        ('asset_type', 'DIR'): '_serialize_ddict',
        ('asset_type', 'LEVELDICTIONARY'): '_serialize_ldict',
    }

    def __init__(self, path: Path | str, build_path: Path | str = None) -> None:
        self.path = Path(path)
        self.name = self.path.stem
        self.chunks = []
        self.endianness = '<'
        if self.path.is_dir():
            self.info_json = self.path.joinpath(f'{self.name}.json')
            if not self.info_json.is_file():
                raise FileNotFoundError('The JSON descriptor was not found.')
            self._build_stream(build_path)

        self.fp = self.path.open('rb')
        self.mm = mmap(self.fp.fileno(), 0, access=ACCESS_READ)
        self.__read_chunks()
        self.num_chunks = len(self.chunks)
        assert sum(self.chunks[0].data.values()) == sum(
            1 for chunk in self.chunks if chunk.type == 'CODE'), 'Code class count missmatch'

    def __repr__(self):
        return f'''
{self.name}
{self.path}
{len(self.chunks)} chunks
Code Classes:\n\t{'\n\t'.join(f"{k} ({v})" for k, v in self.chunks[0].data.items())}
{sum(1 for chunk in self.chunks if chunk.type == 'ASSET' and chunk.asset_type not in ('DIR', 'LEVELDICTIONARY', 'END'))} assets
'''

    def json(self):
        return {'endianness': self.endianness, 'Class count': len(self.chunks[0].data),
                'Chunks': [
                    {k: v for k, v in asdict(chunk).items() if v and k != 'data'} for chunk in self.chunks]}

    def __read_chunks(self) -> None:
        idx = 0
        while True:
            chunk_id, size, version = unpack('<III', self.mm.read(12))
            if chunk_id == 0x71c:
                class_count, = unpack('<I', self.mm.read(4))
                if class_count > 100:  # Should be safe enough
                    self.endianness = '>'
                    self.mm.seek(-4, 1)
                    class_count, = unpack(f'{self.endianness}I', self.mm.read(4))
                class_instances: dict[str:int] = {
                    self._read_arb_str(): unpack(f'{self.endianness}I', self.mm.read(4))[0] for _ in
                    range(class_count)}
                self.mm.seek(8, 1)

                self.chunks.append(CRDChunk(hex(chunk_id), size, version, f'{self.name}_CODE.json', class_instances))

            elif chunk_id == 0x716:
                metadata_size, = unpack(f'{self.endianness}I', self.mm.read(4))
                name = self._read_str()
                guid = UUID(bytes_le=self.mm.read(16))
                asset_type = self._read_str()
                source_path = self._read_str()
                target_path = self._read_str()
                separator = self.mm.read(4).hex(' ').upper()
                data_size, = unpack(f'{self.endianness}I', self.mm.read(4))
                data = self.mm.read(data_size)
                extra = None

                short_name = name.rsplit('\\', maxsplit=1)[-1]
                short_path = source_path.rsplit('\\', maxsplit=1)[-1]
                filename = short_path

                if short_name == 'LevelConfig':
                    filename += '.rws'
                elif short_name.count('.') == 1 and short_name not in short_path and not short_name.endswith('.sdt'):
                    filename = short_name

                if filename.endswith('.swf'):
                    filename = filename.replace('.swf', '.big')  # SWF files are BIGF

                if size > 4206559400:
                    lines = data.decode().splitlines()
                    if asset_type == 'END':
                        filename += '.txt'
                        self.chunks.append(
                            AssetChunk(hex(chunk_id), size, version,
                                       filename, name, guid, asset_type,
                                       source_path, target_path, separator, data))
                        break
                    filename += '.json'
                    it = iter(lines)
                    items = int(next(it))
                    items_total = int(next(it))

                    if asset_type == 'DIR':
                        items_total_converted = int(next(it))
                        data = [{'source_size': items_total,
                                  'target_size': items_total_converted},
                                 *[{'target': next(it), 'source': next(it),
                                    'target_size': int(next(it)),
                                    'source_size': int(next(it))}
                                   for _ in range(items)]]
                    elif asset_type == 'LEVELDICTIONARY':
                        data = {next(it): {next(it): next(it) for _ in range(int(next(it)))}
                                 for _ in range(items)}
                    else:
                        raise NotImplementedError(f'Unknown asset_type: {asset_type}')
                else:
                    if asset_type == 'LOCXML':
                        filename += '.json'
                        bxml = BytesIO(data)
                        data = {'languages': [bxml.read(bxml.read(1)[0] + 1).decode()[:-1] for _ in
                                               range(unpack('<I', bxml.read(4))[0])],
                                 'SKU ID': bxml.read(bxml.read(1)[0]).decode()}

                    elif asset_type in ('LOC', 'MDB'):
                        extra = self._parse_loc(BytesIO(data), asset_type == 'MDB')

                    if extra_bytes := (4 - (data_size % 4)) % 4:
                        self.mm.seek(extra_bytes, 1)

                self.chunks.append(
                    AssetChunk(hex(chunk_id), size, version, filename, name, guid, asset_type, source_path,
                               target_path, separator, data, extra))

            elif chunk_id == 0x704:
                filename = f'{self.name}_CODE_{idx}.dat'
                self.chunks.append(
                    CodeChunk(hex(chunk_id), size, version, filename, self.mm.read(size)))
                idx += 1

            else:
                raise ValueError('Unknown Chunk ID:', chunk_id)

    def _build_stream(self, build_path: Path | str = None) -> None:
        info = json.load(self.info_json.open('r'))
        self.endianness = info['endianness']
        bo = 'little' if self.endianness == '<' else 'big'
        build_path = Path(build_path) if build_path else self.path.with_suffix('.str2')
        chunks = info['Chunks']
        with build_path.open('wb') as fp:
            for chunk in chunks:
                filename = self.path / chunk['filename']
                chunk_id = int(chunk['id'], 0).to_bytes(4, 'little')
                version = chunk['version'].to_bytes(4, 'little')
                metadata = self._pack_asset_metadata(chunk) if chunk['id'] == '0x716' else b''
                file_data = filename.read_bytes()
                if chunk['filename'].endswith('.json'):
                    dict_data = json.loads(file_data)
                    for (key, value), method_name in self.SERIALIZERS.items():
                        if chunk[key] == value:
                            file_data = getattr(self, method_name)(dict_data)
                            break
                file_size = len(file_data)
                file_pad = ((4 - (file_size % 4)) % 4) if chunk['size'] < 4206559400 else 0
                size = chunk['size'].to_bytes(4, 'little') if chunk['size'] > 4206559400 else (
                        (4 if chunk['id'] != '0x704' else 0) + len(metadata) + file_size + file_pad
                ).to_bytes(4, 'little')
                data_size = file_size.to_bytes(4, bo) if chunk['id'] != '0x71c' else info['Class count'].to_bytes(4, bo)
                fp.write(chunk_id + size + version + metadata + (
                    data_size if chunk['id'] != '0x704' else b'') + file_data + file_pad * b'X')
        print('Exported stream', build_path)
        self.path = build_path

    def extract_all(self, output_dir: Path | str | None = None) -> None:
        output_dir = Path(output_dir) if output_dir is not None else self.path.with_suffix('')
        if output_dir.is_file():
            raise ValueError('Output path must be a directory')
        output_dir.mkdir(parents=True, exist_ok=True)
        for chunk in self.chunks:
            data = json.dumps(chunk.data, ensure_ascii=False, indent=4).encode('utf-8') if isinstance(chunk.data, dict | list) else chunk.data
            output_dir.joinpath(chunk.filename).write_bytes(data)
            if getattr(chunk, 'extra', None):
                json.dump(chunk.extra, output_dir.joinpath(chunk.filename).with_suffix(
                    f'{Path(chunk.filename).suffix}.json').open('w', encoding='utf8', newline='\n'),
                          ensure_ascii=False, indent=4)
        json.dump(self.json(),
                  output_dir.joinpath(output_dir.with_suffix('.json').name).open('w', encoding='utf8', newline='\n'),
                  indent=4, ensure_ascii=False, default=self._encode_bytes)

    @staticmethod
    def _encode_bytes(obj: bytes) -> str:
        if isinstance(obj, bytes): return ''
        elif isinstance(obj, UUID): return f'{{{str(obj).upper()}}}'
        raise TypeError(f'Object of type {type(obj).__name__} is not JSON serializable')

    def _pack_asset_metadata(self, chunk: dict) -> bytes:
        metadata = (
            self._pack_padded_string_with_size(chunk.get('name', '')) +
            UUID(chunk['guid'].strip("{}")).bytes_le +
            self._pack_padded_string_with_size(chunk['asset_type']) +
            self._pack_padded_string_with_size(chunk['source_path']) +
            self._pack_padded_string_with_size(chunk.get('target_path', '')) +
            bytes.fromhex(chunk['separator'])
        )
        return len(metadata).to_bytes(4, 'big' if self.endianness == '>' else 'little') + metadata

    def _read_str(self) -> str:
        return self.mm.read(unpack(f'{self.endianness}I', self.mm.read(4))[0]).rstrip(b'!').rstrip(b'\r\n').rstrip(b'\xBF').rstrip(
            b'\0').decode('utf-8')

    def _read_arb_str(self) -> str:
        chunks = []
        while chunk := self.mm.read(4):
            if b'\0' in chunk:
                chunks.append(chunk[:chunk.find(b'\0')])
                break
            chunks.append(chunk)

        return b''.join(chunks).decode('utf-8')

    @staticmethod
    def _pack_padded_string(instr: str) -> bytes:
        outstr = instr.encode() + b'\0'
        lenstr = len(outstr)

        return outstr + b'\xBF' * ((4 - (lenstr % 4)) % 4)

    def _pack_padded_string_with_size(self, instr: str) -> bytes:
        packed = self._pack_padded_string(instr)
        return pack(f'{self.endianness}I', len(packed)) + packed

    def _serialize_crd(self, crd: dict) -> bytes:
        return b''.join(
            self._pack_padded_string(key) + pack(f'{self.endianness}I', value)
            for key, value in crd.items()
        ) + b'\0\xbf\xbf\xbf\0\0\0\0'

    @staticmethod
    def _serialize_locxml(locxml: dict) -> bytes:
        return b''.join((
            len(locxml['languages']).to_bytes(4, 'little'),
            *(
                len(l).to_bytes(1) + l.encode() + b'\0'
                for l in locxml['languages']
            ),
            len(locxml['SKU ID']).to_bytes(1),
            locxml['SKU ID'].encode(),
            b'\0'
        ))

    @staticmethod
    def _serialize_ldict(ldict: dict) -> bytes:
        return '\r\n'.join(
            map(str,
                (len(ldict),
                 sum(map(len, ldict.values())),
                 *(x for k, v in ldict.items() for x in (k, len(v), *sum(v.items(), ()))), '')
                )).encode()

    @staticmethod
    def _serialize_ddict(ddict: dict) -> bytes:
        return '\r\n'.join(map(str,((len(ddict) - 1), *(v for d in ddict for v in d.values()), ''))).encode()

    def _parse_loc(self, loc: BytesIO, mdb: bool = False) -> list:
        if mdb:
            loc.seek(unpack(f'{self.endianness}I', loc.read(4))[0], 1)

        loch_magic, size, flags, num_locl_chunks = unpack('<4sIII', loc.read(16))
        loc.seek(num_locl_chunks * 4, 1)

        if flags:
            loci_magic, size, num_indices = unpack('<4sII4x', loc.read(16))
            loc.seek(num_indices * 4, 1)

        locl_magic, size, lang_id, num_strings = unpack('<4sIII', loc.read(16))
        loc.seek(num_strings * 4, 1)

        return [l.strip('\0') for l in loc.read().decode('utf-16').split('\0\0') if l.strip()]

if __name__ == '__main__':
    recurse = '-r' in sys.argv
    build = '-b' in sys.argv

    recurse and sys.argv.remove('-r')
    build and sys.argv.remove('-b')
    if len(sys.argv) < 2:
        print(f"""Usage: {sys.argv[0]} <path/to/input/file_or_folder> [options]\noptions:
    -r  Recursive
    -b  Build
         """)
        exit(1)

    input_path = Path(sys.argv[1])
    output_base = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if input_path.is_file():
        output_path = output_base.joinpath(input_path.stem) if output_base else input_path.with_suffix('')
        RWStream(input_path).extract_all(output_path)
    elif input_path.is_dir():
        for file in input_path.glob(f'{'**/' if recurse else ''}*{'.json' if build else '.str'}'):
            if build:
                if file.stem == file.parent.name:
                    output_path = output_base.joinpath(file.with_suffix('.str2').name) if output_base else file.parent.with_suffix('.str2')
                    RWStream(file.parent, output_path)
            else:
                output_path = output_base.joinpath(file.with_suffix('').name) if output_base else file.with_suffix('')
                RWStream(file).extract_all(output_path)
