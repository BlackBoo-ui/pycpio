# python module for CPIO archive generation
# supports new ASCII format
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>

from pprint import pprint as pp
import array
import copy
import os
import stat

class icounter(object):
    _counter = 721

    def __int__(self):
        try:
            return self.__counter
        except:
            self.__counter = icounter._counter
            icounter._counter += 1
        return self.__counter

class _struct(object):
    def __getattribute__(self, key):
        if key == 'fields':
            for f in self._fields.keys():
               try:
                   v = object.__getattribute__(self, f)
                   self._fields[f].value = v
               except: pass
            return self._fields
        return object.__getattribute__(self, key)

class _codec(object):
    _counter = 0

    def __init__(self):
        self._counter = _codec._counter
        _codec._counter += 1

class codecMeta(type):
    def __call__(cls, *args, **kw):
        self = type.__call__(cls, *args, **kw)
        self._fields = copy.deepcopy(cls.FIELDS)
        return self

    def __init__(cls, name, bases, dct):
        cls.FIELDS = {}
        for b in bases:
            try: cls.FIELDS.update(b.FIELDS)
            except: pass
        for k,v in dct.iteritems():
            if isinstance(v, _codec):
                n = k.lower()
                v.name = n
                cls.FIELDS[n] = v
        super(codecMeta, cls).__init__(name, bases, dct)

class struct(_struct):
    __metaclass__ = codecMeta

    def __init__(self):
        super(struct, self).__init__()

    def pack(self, blob):
        fields = self.fields.values()
        fields.sort(key=lambda x: x._counter)
        for f in fields:
            f.pack(blob)

    class blob(_codec):
        def __init__(self, value=''):
            self.value = value
            super(struct.blob, self).__init__()

        def pack(self, blob):
            blob.extend(self.value)

    class string(_codec):
        def __init__(self, value=''):
            self.value = value
            super(struct.string, self).__init__()

        def pack(self, blob):
            if self.value:
                blob.extend(self.value + '\0')

    class xuint(_codec):
        def __init__(self, value=0):
            self.value = value
            super(struct.xuint, self).__init__()

        def pack(self, blob):
            blob.extend('%08X' % int(self.value))

    class align(_codec):
        def __init__(self, alignment=4):
            self.alignment = alignment
            super(struct.align, self).__init__()

        def pack(self, blob):
            rem = len(blob) % self.alignment
            if rem:
                blob.extend('\0' * (self.alignment - rem))

class _node(struct):
    MAGIC = struct.blob("070701")
    INO = struct.xuint(icounter())
    MODE = struct.xuint()
    UID = struct.xuint()
    GID = struct.xuint()
    NLINK = struct.xuint(1)
    MTIME = struct.xuint()
    FILESIZE = struct.xuint()
    DEVMAJOR = struct.xuint(3)
    DEVMINOR = struct.xuint(1)
    RDEVMAJOR = struct.xuint()
    RDEVMINOR = struct.xuint()
    NAMESIZE = struct.xuint()
    CHECK = struct.xuint()
    NAME = struct.string()
    NALIGN = struct.align()

    def __init__(self, path, **attributes):
        if path.startswith('/'):
            path = path[1:]
        self.name = path
        self.namesize = len(self.name) + 1
        for k,v in attributes.iteritems():
            setattr(self, k, v)

class trailer(_node):
    ALIGN = struct.align(512)

    def __init__(self):
        self.ino = 0
        self.devmajor = 0
        self.devminor = 0
        super(trailer, self).__init__('TRAILER!!!')

class symlink(_node):
    TARGET = struct.string()
    TALIGN = struct.align()

    def __init__(self, path, target, **attributes):
        self.target = target
        self.filesize = len(target) + 1
        super(symlink, self).__init__(path, **attributes)

class dev(_node):
    def __init__(self, path, major, minor, **attributes):
        self.rdevmajor = major
        self.rdevminor = minor
        super(dev, self).__init__(path, **attributes)

class nod(_node):
    def __init__(self, path, **attributes):
        super(nod, self).__init__(path, **attributes)

class reg(_node):
    DATA = struct.blob()
    DALIGN = struct.align()

    def __init__(self, path, data, **attributes):
        self.data = data
        self.filesize = len(data)
        super(reg, self).__init__(path, **attributes)

class nodeMeta(type):
    def __call__(cls, root, path, *args, **kw):
        fpath = os.path.join(root, path)
        st = os.lstat(fpath)
        attrs = {}
        for a in ['mode', 'uid', 'gid', 'mtime']:
            attrs[a] = getattr(st, 'st_' + a)
        mode = attrs['mode']
        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            rdev = st.st_rdev
            major = (rdev>>16)&0xFFFF
            minor = rdev&0xFFFF
            return dev(path, minor, major, **attrs)
        elif stat.S_ISLNK(mode):
            target = os.readlink(fpath)
            return symlink(path, target, **attrs)
        elif stat.S_ISREG(mode):
            data = file(fpath).read()
            return reg(path, data, **attrs)
        else:
            return nod(path, **attrs)

class node(object):
    __metaclass__ = nodeMeta

class cpio(object):
    def __init__(self):
        self.__nodes = []

    def pack(self):
        blob = array.array('c')
        for n in self.__nodes:
            n.pack(blob)
        trailer().pack(blob)
        return blob

    def tofile(self, file):
        self.pack().tofile(file)

    def push(self, node):
        self.__nodes.append(node)

    def force(self, key, value):
        for n in self.__nodes:
            setattr(n, key, value)

    def traverse(self, target):
        def norm(root, p):
            return os.path.join(root, p).replace(target, '')
        for root, dirs, files in os.walk(target):
            for f in files:
                self.push(node(target, norm(root, f)))
            for d in dirs:
                self.push(node(target, norm(root, d)))

def main(args):
    target = args.pop(0)
    archive = args.pop(0)
    a = cpio()
    a.traverse(target)
    a.force('mtime', 0)
    a.tofile(file(archive, 'w+'))

if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
