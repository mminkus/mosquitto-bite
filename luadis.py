#!/usr/bin/env python3
"""Minimal Lua 5.1 bytecode disassembler."""
import struct, sys

OPS = """MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL SETUPVAL
SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE
TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORLOOP SETLIST CLOSE CLOSURE
VARARG""".split()

class R:
    def __init__(s, b):
        s.b = b; s.i = 0
    def raw(s, n):
        v = s.b[s.i:s.i+n]; s.i += n; return v
    def byte(s):
        return s.raw(1)[0]
    def int(s):
        return struct.unpack('<i', s.raw(4))[0]
    def size(s, sz):
        return struct.unpack('<I' if sz == 4 else '<Q', s.raw(sz))[0]
    def num(s):
        return struct.unpack('<d', s.raw(8))[0]

def read_string(r, szsize):
    n = r.size(szsize)
    if n == 0: return None
    return r.raw(n)[:-1].decode('latin1')

def read_func(r, szsize):
    f = {}
    f['source'] = read_string(r, szsize)
    f['line'] = r.int(); f['lastline'] = r.int()
    f['nups'] = r.byte(); f['nparams'] = r.byte()
    f['vararg'] = r.byte(); f['maxstack'] = r.byte()
    n = r.int(); f['code'] = [struct.unpack('<I', r.raw(4))[0] for _ in range(n)]
    n = r.int(); ks = []
    for _ in range(n):
        t = r.byte()
        if t == 0: ks.append(None)
        elif t == 1: ks.append(bool(r.byte()))
        elif t == 3: ks.append(r.num())
        elif t == 4: ks.append(read_string(r, szsize))
        elif t == 9: ks.append(r.int())   # LUA_TINT, OpenWrt LNUM patch
        else: raise ValueError('const type %d' % t)
    f['k'] = ks
    n = r.int(); f['protos'] = [read_func(r, szsize) for _ in range(n)]
    n = r.int(); f['lineinfo'] = [r.int() for _ in range(n)]
    n = r.int(); f['locvars'] = [(read_string(r, szsize), r.int(), r.int()) for _ in range(n)]
    n = r.int(); f['upvals'] = [read_string(r, szsize) for _ in range(n)]
    return f

def kstr(f, i):
    v = f['k'][i] if i < len(f['k']) else '?'
    return repr(v)

def rk(f, x):
    return kstr(f, x & 0xff) if x & 0x100 else 'R%d' % x

def dis(f, name='main', out=sys.stdout):
    print('\n=== %s  line %d-%d  params=%d ups=%d stack=%d' % (
        name, f['line'], f['lastline'], f['nparams'], f['nups'], f['maxstack']), file=out)
    for pc, ins in enumerate(f['code']):
        op = ins & 0x3f; a = (ins >> 6) & 0xff
        c = (ins >> 14) & 0x1ff; b = (ins >> 23) & 0x1ff
        bx = (ins >> 14) & 0x3ffff; sbx = bx - 131071
        o = OPS[op] if op < len(OPS) else 'OP%d' % op
        line = f['lineinfo'][pc] if pc < len(f['lineinfo']) else 0
        arg = ''
        if o in ('LOADK',): arg = 'R%d := %s' % (a, kstr(f, bx))
        elif o in ('GETGLOBAL',): arg = 'R%d := _G[%s]' % (a, kstr(f, bx))
        elif o in ('SETGLOBAL',): arg = '_G[%s] := R%d' % (kstr(f, bx), a)
        elif o == 'GETTABLE': arg = 'R%d := R%d[%s]' % (a, b, rk(f, c))
        elif o == 'SETTABLE': arg = 'R%d[%s] := %s' % (a, rk(f, b), rk(f, c))
        elif o == 'SELF': arg = 'R%d,R%d := R%d[%s],R%d' % (a, a+1, b, rk(f, c), b)
        elif o == 'GETUPVAL': arg = 'R%d := U%d(%s)' % (a, b, f['upvals'][b] if b < len(f['upvals']) else '?')
        elif o == 'SETUPVAL': arg = 'U%d(%s) := R%d' % (b, f['upvals'][b] if b < len(f['upvals']) else '?', a)
        elif o == 'CALL': arg = 'R%d(nargs=%s nres=%s)' % (a, b-1 if b else 'var', c-1 if c else 'var')
        elif o == 'TAILCALL': arg = 'return R%d(nargs=%s)' % (a, b-1 if b else 'var')
        elif o == 'RETURN': arg = 'return R%d..%s' % (a, b-1 if b else 'top')
        elif o == 'JMP': arg = '-> %d' % (pc+1+sbx)
        elif o in ('EQ','LT','LE'): arg = 'if (%s %s %s) ~= %d then pc++' % (rk(f,b), o, rk(f,c), a)
        elif o == 'TEST': arg = 'if not R%d == %d then pc++' % (a, c)
        elif o == 'TESTSET': arg = 'if R%d == %d then R%d := R%d else pc++' % (b, c, a, b)
        elif o == 'CONCAT': arg = 'R%d := concat(R%d..R%d)' % (a, b, c)
        elif o == 'CLOSURE': arg = 'R%d := closure #%d' % (a, bx)
        elif o == 'MOVE': arg = 'R%d := R%d' % (a, b)
        elif o == 'LOADNIL': arg = 'R%d..R%d := nil' % (a, b)
        elif o == 'LOADBOOL': arg = 'R%d := %s%s' % (a, bool(b), ' ; skip' if c else '')
        elif o == 'NEWTABLE': arg = 'R%d := {}' % a
        elif o == 'NOT': arg = 'R%d := not R%d' % (a, b)
        elif o == 'LEN': arg = 'R%d := #R%d' % (a, b)
        elif o in ('ADD','SUB','MUL','DIV','MOD','POW'): arg = 'R%d := %s %s %s' % (a, rk(f,b), o, rk(f,c))
        elif o == 'FORPREP': arg = '-> %d' % (pc+1+sbx)
        elif o == 'FORLOOP': arg = '-> %d' % (pc+1+sbx)
        else: arg = 'A=%d B=%d C=%d' % (a, b, c)
        print('  [%4d] L%-5d %-10s %s' % (pc, line, o, arg), file=out)
    for i, p in enumerate(f['protos']):
        dis(p, '%s/closure#%d' % (name, i), out)

def load(path):
    b = open(path, 'rb').read()
    assert b[:4] == b'\x1bLua', 'not lua bytecode'
    assert b[4] == 0x51, 'not lua 5.1'
    szsize = b[8]
    r = R(b); r.i = 12
    f = read_func(r, szsize)
    assert r.i == len(b), 'trailing %d bytes' % (len(b)-r.i)
    return f

if __name__ == '__main__':
    f = load(sys.argv[1])
    dis(f)
