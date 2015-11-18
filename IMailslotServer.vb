Public Interface IMailslotServer

    Function Connect() As Boolean
    Sub Disconnect()
    Function Read() As Boolean

End Interface
