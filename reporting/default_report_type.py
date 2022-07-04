fieldnames = [
    "ConsignmentReference", "ConsignmentType", "TransferringBodyName", "BodyCode",
    "SeriesCode", "ConsignmentId", "UserId", "CreatedDateTime", "TransferInitiatedDatetime", "ExportDateTime",
    "ExportLocation", "FileCount", "TotalSize(Bytes)"]


def node_to_dict(node):
    return {
        "ConsignmentReference": node.consignmentReference,
        "ConsignmentType": node.consignmentType,
        "TransferringBodyName": node.transferringBody.name,
        "BodyCode": node.transferringBody.tdrCode,
        "SeriesCode": node.series.code if hasattr(node.series, 'code') else '',
        "ConsignmentId": node.consignmentid,
        "UserId": node.userid,
        "CreatedDateTime": node.createdDatetime,
        "TransferInitiatedDatetime": node.transferInitiatedDatetime if hasattr(node,
                                                                               'transferInitiatedDatetime') else '',
        "ExportDateTime": node.exportDatetime,
        "ExportLocation": node.exportLocation,
        "FileCount": len(node.files),
        "TotalSize(Bytes)": 0 if not node.files else sum(
            filter(None, (item.metadata.clientSideFileSize for item in node.files)))
    }
