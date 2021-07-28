#Công cụ quét lỗ hổng xss
#HƯỚNG DẪN:
#- Công cụ có 4 tùy chọn( -u, -p, --Proxy, -c):
	-u --Url( Url cần quét - là tùy chọn bắt buộc.
	-p --Param( tùy chọn này cho phép nhập từng parameter cho form): với tùy chọn này sẽ phải nhập 1 giá trị đại diện cho chuỗi 
javascript, với option này sau khi nhập chuỗi đại diện sẽ phải nhập ít nhất 1 chuỗi đại diện này vào 1 parameter nào đó.
	--Proxy ( tùy chọn này cho phép quét với proxy)
	-c --Cookie (tùy chọn này cho phép gửi request với cookie nhập vào)
#Ví dụ: XSS_Scanner.py -u 'http://testphp.vulnweb.com/search.php?test=query' -p --Proxy 'HTTPS://115.77.191.180:53281'

