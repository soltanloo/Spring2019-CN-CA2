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
        startLine = request.split(b'\r\n')[0].split(b' ')
        parsedRequest['method'] = startLine[0]
        parsedRequest['url'] = startLine[1]
        parsedRequest['httpVersion'] = startLine[2]

        restOfRequest = request.split(b'\r\n', 1)[1].split(b'\r\n\r\n')
        headers = restOfRequest[0].split(b'\r\n')
        for header in headers:
            splitHeader = header.split(b': ', 1)
            parsedRequest['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfRequest) > 1:
            parsedRequest['body'] = restOfRequest[1]

        portPos = parsedRequest['headers'][b'Host'].find(b':')  # find the port pos (if any)
        if portPos == -1:  # default port
            port = 80
            webserver = parsedRequest['headers'][b'Host']
        else:  # specific port
            port = int(parsedRequest['headers'][b'Host'][(portPos + 1):])
            webserver = parsedRequest['headers'][b'Host'][:portPos]

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
        startLine = response.split(b'\r\n')[0].split(b' ', 2)
        parsedResponse['httpVersion'] = startLine[0]
        parsedResponse['statusCode'] = startLine[1]
        parsedResponse['statusMessage'] = startLine[2]

        restOfResponse = response.split(b'\r\n', 1)[1].split(b'\r\n\r\n')
        headers = restOfResponse[0].split(b'\r\n')
        for header in headers:
            splitHeader = header.split(b': ', 1)
            parsedResponse['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfResponse) > 1:
            parsedResponse['body'] = restOfResponse[1]
        return parsedResponse

    @staticmethod
    def serializeHTTPResponse(response):
        pass
