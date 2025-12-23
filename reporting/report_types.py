class Report:
    pass


class StandardReport(Report):
    def __init__(self):
        self.fieldnames = [
            "ConsignmentReference", "ConsignmentType", "TransferringBodyName", "TransferringBodyTdrCode",
            "SeriesCode", "ConsignmentId", "UserId", "CreatedDateTime", "TransferInitiatedDatetime", "ExportDateTime",
            "ExportLocation", "FileCount", "TotalSize(Bytes)"]

    @staticmethod
    def node_to_dict(node):
        return {
            "ConsignmentReference": node.consignmentReference,
            "ConsignmentType": node.consignmentType,
            "TransferringBodyName": node.transferringBodyName,
            "TransferringBodyTdrCode": node.transferringBodyTdrCode,
            "SeriesCode": node.seriesName,
            "ConsignmentId": node.consignmentid,
            "UserId": node.userid,
            "CreatedDateTime": node.createdDatetime,
            "TransferInitiatedDatetime": node.transferInitiatedDatetime if hasattr(node,
                                                                                   'transferInitiatedDatetime') else '',
            "ExportDateTime": node.exportDatetime,
            "ExportLocation": node.exportLocation,
            "FileCount": node.totalFiles,
            "TotalSize(Bytes)": node.totalFileSize
        }

    @staticmethod
    def edge_filter(_):
        return True


class CaseLawReport(Report):
    def __init__(self):
        self.fieldnames = ['CreatedDateTime', 'ConsignmentReference', 'ConsignmentId', 'ConsignmentType', 'UserId',
                           'ExportDateTime']

    @staticmethod
    def node_to_dict(node):
        return {
            "CreatedDateTime": node.createdDatetime,
            "ConsignmentReference": node.consignmentReference,
            "ConsignmentId": node.consignmentid,
            "ConsignmentType": node.consignmentType,
            "UserId": node.userid,
            "ExportDateTime": node.exportDatetime
        }

    @staticmethod
    def edge_filter(edge):
        return edge.node.consignmentType == "judgment"


class FileCheckFailuresReport(Report):
    def __init__(self):
        self.fieldnames = [
            'FileId', 'ConsignmentId', 'ConsignmentType', 'RankOverFilePath', 'PUID',
            'UserId', 'StatusType', 'StatusValue', 'SeriesName', 'TransferringBodyName',
            'AntivirusResult', 'Extension', 'IdentificationBasis', 'ExtensionMismatch',
            'FormatName', 'Checksum', 'CreatedDateTime'
        ]

    @staticmethod
    def failure_to_dict(failure):
        return {
            'FileId': failure.fileId,
            'ConsignmentId': failure.consignmentId,
            'ConsignmentType': failure.consignmentType,
            'RankOverFilePath': failure.rankOverFilePath,
            'PUID': failure.PUID or '',
            'UserId': failure.userId,
            'StatusType': failure.statusType,
            'StatusValue': failure.statusValue,
            'SeriesName': failure.seriesName or '',
            'TransferringBodyName': failure.transferringBodyName or '',
            'AntivirusResult': failure.antivirusResult or '',
            'Extension': failure.extension or '',
            'IdentificationBasis': failure.identificationBasis or '',
            'ExtensionMismatch': failure.extensionMismatch,
            'FormatName': failure.formatName or '',
            'Checksum': failure.checksum or '',
            'CreatedDateTime': failure.createdDateTime,
        }

    @staticmethod
    def failure_filter(_):
        return True
