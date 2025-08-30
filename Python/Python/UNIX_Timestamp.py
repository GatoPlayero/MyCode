from struct import pack, unpack
from datetime import datetime, timezone

def sick_timestamp_to_datetime(ts):
    double_value, = unpack("d", ts.to_bytes((ts.bit_length() + 7) // 8, "big"))
    return datetime.fromtimestamp(double_value * 1000000, timezone.utc)

def datetime_to_sick_timestamp(dt):
    double_value = dt.timestamp() / 1000000
    return int.from_bytes(pack("d", double_value), "big")

_TicketId_AsUnixTimestamp = datetime_to_sick_timestamp(datetime.now(timezone.utc))
print(_TicketId_AsUnixTimestamp)

## 7,010,360,662,527,744,576
## 6,852,852,392,033,425,984
## 9,223,372,036,854,775,808	<<<<< SQL Server BigInt

## ----------------------------------------------------------------------------------------------------

from datetime import datetime, timezone
import time

## ref https://www.geeksforgeeks.org/how-to-convert-datetime-to-unix-timestamp-in-python/
_TicketId_AsUnixTimestamp = int(datetime.timestamp(datetime.now(timezone.utc)))
## _TicketId_AsUnixTimestampMiliSeconds = int(time.mktime((datetime.now(timezone.utc)).timetuple()) * 1000) ## NO USAR
print(_TicketId_AsUnixTimestamp)
## print(_TicketId_AsUnixTimestampMiliSeconds) ## NO USAR

print('wait')

#$UTCDateTime = (Get-Date).ToUniversalTime();
#$Start1970 = [timezone]::CurrentTimeZone.ToLocalTime([datetime]'1/1/1970');
#$UnixTimeStamp = (New-TimeSpan -Start $Start1970 -End $UTCDateTime).TotalSeconds;
#$UnixTimeStamp = [double]([System.Math]::Truncate($UnixTimeStamp));