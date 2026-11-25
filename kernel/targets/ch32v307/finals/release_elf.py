"""Canonicalize the assembler's non-loaded STT_FILE name in a WCH RV32 firmware ELF."""
import argparse
import hashlib
import re
import struct
from pathlib import Path, PureWindowsPath

ELF = struct.Struct("<16sHHIIIIIHHHHHH")
SECTION = struct.Struct("<10I")
PROGRAM = struct.Struct("<8I")
SYMBOL = struct.Struct("<IIIBBH")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(raw):
    header = list(ELF.unpack_from(raw))
    if header[0][:6] != b"\x7fELF\x01\x01" or header[2] != 243:
        raise ValueError("WCH little-endian RISC-V ELF32 required")
    if (header[8],header[9],header[11]) != (ELF.size, PROGRAM.size, SECTION.size):
        raise ValueError("unexpected header entry sizes")
    sections = [list(SECTION.unpack_from(raw,header[6]+i*SECTION.size)) for i in range(header[12])]
    programs = [PROGRAM.unpack_from(raw,header[5]+i*PROGRAM.size) for i in range(header[10])]
    return header, sections, programs


def bytes_of(raw, sh):
    return bytes(raw[sh[4]:sh[4]+sh[5]]) if sh[1] != 8 else b""


def string(table, i):
    return table[i:table.index(0,i)]


def inspect(raw):
    header, sections, programs=unpack(raw)
    names=bytes_of(raw,sections[header[13]])
    rows=[]; file_names=[]; semantic_sections=[]
    for sh in sections:
        sec_name=string(names,sh[0]).decode()
        if sh[1] == 2:
            strings = bytes_of(raw,sections[sh[6]])
            for off in range(sh[4],sh[4]+sh[5],sh[9]):
                name,*fields = SYMBOL.unpack_from(raw,off)
                text=string(strings,name).decode()
                if fields[2] & 15 == 4:
                    file_names.append(text)
                    text=PureWindowsPath(text).name
                rows.append((text,*fields))
        if sec_name not in (".symtab",".strtab",".shstrtab"):
            semantic_sections.append((sec_name,tuple(sh[1:]),sha(bytes_of(raw,sh))))
    loads=[(p,sha(raw[p[1]:p[1]+p[4]])) for p in programs]
    return (header[1:6],header[7:],semantic_sections,rows,loads),file_names


def canonical(raw):
    header, sections, programs=unpack(raw)
    if header[6]+header[12]*SECTION.size != len(raw):
        raise ValueError("unsupported trailing ELF data")
    name_section=sections[header[13]]
    names = bytes_of(raw,name_section)
    indexes={string(names,sh[0]).decode(): i for i,sh in enumerate(sections)}
    si,ti,ni=(indexes[k] for k in (".symtab",".strtab",".shstrtab"))
    sy,st,ns=(sections[i] for i in (si,ti,ni))
    if not (sy[1]==2 and sy[6]==ti and st[1]==ns[1]==3 and not (st[2] | ns[2])
            and st[4]+st[5]==ns[4] and ns[4]+ns[5]<=header[6]
            and not any(raw[ns[4]+ns[5]:header[6]]) and sy[4]+sy[5]<=st[4]):
        raise ValueError("unrecognized WCH string and section table layout")
    if any(sh[6]==ti for i,sh in enumerate(sections) if i!=si):
        raise ValueError("additional string-table consumers")
    if any(p[4] and p[1]+p[4]>sy[4] for p in programs):
        raise ValueError("loaded data overlaps symbol metadata")
    strings = bytes_of(raw,st)
    offsets=range(sy[4],sy[4]+sy[5],sy[9])
    records=[SYMBOL.unpack_from(raw,off) for off in offsets]
    cuts={}
    for name,_,_,info,_,_ in records:
        val=string(strings,name)
        if info&15==4 and (b"/" in val or b"\\" in val):
            prefix=max(val.rfind(b"/"),val.rfind(b"\\"))+1
            if not val[prefix:]:
                raise ValueError("empty assembler object name")
            cuts[name]=name+prefix
    if not cuts:
        return bytes(raw)
    ranges=sorted(cuts.items())
    if any(b>c for (_,b),(c,_) in zip(ranges,ranges[1:])):
        raise ValueError("ambiguous overlapping source names")
    compacted=bytearray()
    last=0
    for start,end in ranges:
        compacted.extend(strings[last:start])
        last=end
    compacted.extend(strings[last:])
    out=bytearray(raw[:st[4]])
    for off,(name,_,_,info,_,_) in zip(offsets,records):
        if any(start<name<end or name==start and info&15!=4 for start,end in ranges):
            raise ValueError("an independent symbol uses the removed directory")
        index=name-sum(end-start for start,end in ranges if end<=name)
        struct.pack_into("<I",out,off,index)
    out.extend(compacted)
    st[5]=len(compacted)
    ns[4]=len(out)
    out.extend(names)
    out.extend(b"\0"*((-len(out)) % 4))
    header[6]=len(out)
    for sh in sections:
        out.extend(SECTION.pack(*sh))
    ELF.pack_into(out,0,*header)
    result=bytes(out)
    before,_=inspect(raw);after,fn=inspect(result)
    if before != after or any("/" in f or "\\" in f for f in fn):
        raise ValueError("linked symbols or load metadata changed")
    if re.search(rb"[A-Za-z]:[\\/]",result):
        raise ValueError("additional absolute drive path in result")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input",type=Path);parser.add_argument("output",type=Path)
    args=parser.parse_args()
    if args.input.resolve()==args.output.resolve() or args.output.exists():
        raise ValueError("use a new destination file")
    raw=args.input.read_bytes();result=canonical(raw)
    if canonical(result)!=result:
        raise ValueError("canonicalization is not idempotent")
    args.output.write_bytes(result)
    print("source-ELF",sha(raw),"release-ELF",sha(result))


if __name__=="__main__":
    main()
