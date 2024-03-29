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
