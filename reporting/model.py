from sgqlc.types import Type, Field, list_of
from sgqlc.types.relay import Connection


class FileMetadata(Type):
    clientSideFileSize = Field(int)


class File(Type):
    fileId = Field(str)
    metadata = Field(FileMetadata)


class TransferringBody(Type):
    name = Field(str)
    tdrCode = Field(str)


class Series(Type):
    code = Field(str)
    name = Field(str)


class Consignment(Type):
    consignmentid = Field(str)
    consignmentType = Field(str)
    consignmentReference = Field(str)
    userid = Field(str)
    exportDatetime = Field(str)
    exportLocation = Field(str)
    createdDatetime = Field(str)
    transferInitiatedDatetime = Field(str)
    files = list_of(File)
    transferringBody = Field(TransferringBody)
    series = Field(Series)


class Edge(Type):
    node = Field(Consignment)
    cursor = Field(str)


class Consignments(Connection):
    edges = list_of(Edge)
