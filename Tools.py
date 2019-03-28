class Tools:
    @staticmethod
    def deserializeHTTPRequest(request):
        parsedRequest = {
            'webserver': {},
            'method': "",
            'url': "",
            'httpVersion': "",
            'headers': {},
            'body': ""
        }
        startLine = request.split('\r\n')[0].split(' ')
        parsedRequest['method'] = startLine[0]
        parsedRequest['url'] = startLine[1]
        parsedRequest['httpVersion'] = startLine[2]

        restOfRequest = request.split('\r\n', 1)[1].split('\r\n\r\n')
        headers = restOfRequest[0].split('\r\n')
        for header in headers:
            splitHeader = header.split(': ', 1)
            parsedRequest['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfRequest) > 1:
            parsedRequest['body'] = restOfRequest[1]

        portPos = parsedRequest['headers']['Host'].find(":")  # find the port pos (if any)
        if portPos == -1:  # default port
            port = 80
            webserver = parsedRequest['headers']['Host']
        else:  # specific port
            port = int(parsedRequest['headers']['Host'][(portPos + 1):])
            webserver = parsedRequest['headers']['Host'][:portPos]

        parsedRequest['webserver']['address'] = webserver
        parsedRequest['webserver']['port'] = port

        return parsedRequest

    @staticmethod
    def serializeHTTPRequest(request):
        pass

    @staticmethod
    def deserializeHTTPResponse(response):
        parsedResponse = {
            'statusCode': "",
            'statusMessage': "",
            'httpVersion': "",
            'headers': {},
            'body': ""
        }
        startLine = response.split('\r\n')[0].split(' ')
        parsedResponse['httpVersion'] = startLine[0]
        parsedResponse['statusCode'] = startLine[1]
        parsedResponse['statusMessage'] = startLine[2]

        restOfResponse = response.split('\r\n', 1)[1].split('\r\n\r\n')
        headers = restOfResponse[0].split('\r\n')
        for header in headers:
            splitHeader = header.split(': ', 1)
            parsedResponse['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfResponse) > 1:
            parsedResponse['body'] = restOfResponse[1]
        return parsedResponse

    @staticmethod
    def serializeHTTPResponse(response):
        pass
