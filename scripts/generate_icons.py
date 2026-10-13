import struct
import zlib
from pathlib import Path

def icon(size):
    rows=[]
    for y in range(size):
        row=bytearray()
        for x in range(size):
            px, py=x*32/size, y*32/size
            h=8<=py<24 and (8<=px<13 or 19<=px<24 or 13<=px<19 and 14<=py<18)
            row.extend((196,233,155,255) if h else (16,23,18,255))
        rows.append(b'\0'+row)
    def chunk(kind,data):
        return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',size,size,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows)))+chunk(b'IEND',b'')
for size in (192,512):
    Path(f'web/public/icon-{size}.png').write_bytes(icon(size))
