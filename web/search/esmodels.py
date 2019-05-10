from datetime import datetime

from elasticsearch_dsl import *
from elasticsearch_dsl.connections import connections

# Define a default Elasticsearch client
connection = connections.create_connection(hosts=['es', 'localhost'])
path_analyzer = analysis.analyzer('path', tokenizer='path_hierarchy')
entitlement_key_analyzer = analysis.analyzer('entitlement_key',
                                             tokenizer='char_group',
                                             tokenize_on_chars=['-', '.']
                                             )


class Import(InnerDoc):
    name = Text()
    demname = Text()
    flagname = Text()
    ordinal = Long()
    bind = Keyword()
    size = Long()
    type = Keyword()
    vaddr = Long()
    paddr = Long()


class Export(InnerDoc):
    name = Text()
    ordinal = Long()
    bind = Keyword()
    type = Keyword()
    plt = Long()


class Segment(InnerDoc):
    name = Text()
    flags = Text()


class Executable(Document):
    raw_path = Text(analyzer=path_analyzer)
    path = Text()
    strings = Text()

    info = Object()
    libraries = Text(analyzer=path_analyzer, multi=True)
    imports = Nested(Import)
    exports = Nested(Export)
    segments = Nested(Segment)

    class Index:
        name = 'executable-*'


class Method(InnerDoc):
    name = Text()
    addr = Long()


class Field(InnerDoc):
    name = Text()
    addr = Long()


class Clazz(InnerDoc):
    classname = Text()
    methods = Nested(Method)
    fields = Nested(Field)
    index = Long()
    addr = Long()


class RPath(InnerDoc):
    prefix = Keyword()
    path = Text(analyzer=path_analyzer)


class MachO(Executable):
    classdump = Text()
    classes = Nested(Clazz)
    rpaths = Nested(RPath)

    # code signature
    ent = Text()  # json
    ent_str = Text()  # xml
    ent_keys = Text(analyzer=entitlement_key_analyzer,
                    multi=True, fields={'raw': Keyword()})

    cs_flags = Long()
    cs_flags_str = Keyword(multi=True)
    lv = Boolean()
    signed = Boolean()
    apple = Boolean()

    codesign = Text()
    info_plist = Text()  # json
    info_plist_str = Text()  # xml

    class Index:
        name = 'macho-*'


if __name__ == "__main__":
    i = Index('macho-10.14.2')
    i.delete()
    # i.save()
    index = MachO._index.as_template('macho-test')
    index.save()
