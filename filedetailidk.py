class docdetail:
    def __init__(self, FileID, FileName, Status, AccessLevel):
        self.__FileID = FileID
        self.__FileName = FileName
        self.__Status = Status
        self.__AccessLevel = AccessLevel
    
    def get_fileid(self):
        return self.__FileID

    def set_fileid(self, value):
        self.__FileID = value

    def get_filename(self):
        return self.__FileName

    def set_filename(self, value):
        self.__FileName = value

    def get_status(self):
        return self.__Status

    def set_status(self, value):
        self.__Status = value

    def get_accesslevel(self):
        return self.__AccessLevel

    def set_accesslevel(self, value):
        self.__AccessLevel = value

    