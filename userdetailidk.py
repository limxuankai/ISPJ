class userdetail:
    def __init__(self, User, UserRole, UserLevel, id):
        self.__User = User
        self.__UserRole = UserRole
        self.__UserLevel = UserLevel
        self.__id = id
    
    def get_user(self):
        return self.__User

    def set_user(self, value):
        self.__User = value

    def get_userrole(self):
        return self.__UserRole

    def set_userrole(self, value):
        self.__UserRole = value

    def get_userlevel(self):
        return self.__UserLevel

    def set_userlevel(self, value):
        self.__UserLevel = value

    def get_id(self):
        return self.__id

    def set_id(self, value):
        self.__id = value

    