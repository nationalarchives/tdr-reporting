from sgqlc.types import Type, Field, list_of, Input
from sgqlc.types.relay import Connection


class FileMetadata(Type):
    clientSideFileSize = Field(int)


class File(Type):
    fileId = Field(str)
    metadata = Field(FileMetadata)


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
    totalFiles = Field(str)
    totalFileSize = Field(str)
    transferringBodyName = Field(str)
    transferringBodyTdrCode = Field(str)
    seriesName = Field(str)


class Edge(Type):
    node = Field(Consignment)
    cursor = Field(str)


class Consignments(Connection):
    edges = list_of(Edge)

class FileCheckFailure(Type):
    fileId = Field(str)
    consignmentId = Field(str)
    consignmentType = Field(str)
    rankOverFilePath = Field(int)
    PUID = Field(str)
    userId = Field(str)
    statusType = Field(str)
    statusValue = Field(str)
    seriesName = Field(str)
    transferringBodyName = Field(str)
    antivirusResult = Field(str)
    extension = Field(str)
    identificationBasis = Field(str)
    extensionMismatch = Field(bool)
    formatName = Field(str)
    checksum = Field(str)
    createdDateTime = Field(str)

class GetFileCheckFailuresInput(Input):
    consignmentId = Field(str)
    startDateTime = Field(str)
    endDateTime = Field(str)
