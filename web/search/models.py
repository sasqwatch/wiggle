from django.db import models
from django.db.models import TextField, CharField, BooleanField, DateField, IntegerField

from libs.field import JSONField

'''
# IMPORTANT #

Models defined here are only for data import / export, in SQLite3 backend.
The main storage backend is ElasticSearch.

'''

class Executable(models.Model):
    raw_path = TextField()
    path = TextField(unique=True)  # relative to sysroot
    strings = TextField()

    # radare2
    # FIXME: rename this field to info
    meta = JSONField()  # iIj
    libraries = JSONField()  # ilj
    imports = JSONField()  # iij
    exports = JSONField()  # iEj
    segments = JSONField()  # iSj
    entries = JSONField()  # ieej

    # datetime
    created = DateField()
    modified = DateField()
    added = DateField()


class MachO(Executable):
    classdump = TextField()
    classes = JSONField()
    rpaths = JSONField()

    # code signature
    ent = JSONField(default={})
    ent_str = TextField()
    ent_keys = JSONField(default=[])

    cs_flags = IntegerField(default=0)
    cs_flags_str = TextField()
    lv = BooleanField(default=False)
    signed = BooleanField(default=False)
    apple = BooleanField(default=False)

    codesign = TextField()  # codesign -dvvv
    info_plist = JSONField()
    info_plist_str = TextField()


# TODO: add support for PE
class PE(Executable):
    # radare2
    version = JSONField()  # iVj
