# VoIP fraud

## Introduction

Currently, VoIP systems are very often used in business, they replace the standard telephony systems because they are cheaper, expandable and more flexible.

Following the growth of VoIP marker, the fraud market is also growing.

The main scenarios for fraud are the generation of a large number of calls to expensive destinations. The destination operator pays back part of the revenue to a hacker.

These operators exist in many countries of the world.

A separate direction is a case when an operator organizes a joint with large VoIP terminators directly, so most of the cost is sent to it and there are no restrictions on the channels.

## Methodology

For research, i create honeypot what mimics vulnerable PBX.

For emulation, i use Kamailio nodes what send any calls to termination node and answers to OPTIONS and REGISTER.

For every INVITE I record from, to, UA, callId, IP and call time.

Termination node has Kamailio with Flask app for preprocessing calls and Asterisk for topology hiding when calls sent to PSTN.

All calls with a cost of more than 2 cents per minute were rejected with code 486.


#### Sensor node

All data has been written to Redis using this code:

~~~kamailio
$var(json) = '{"from": "' + $fU + '", "to": "' + $rU + '", "ip": "' + $si + '", "ua": "' + $ua +'", "ci": "' + $ci + '", "ts": "' + $TV(s) +'"}';
redis_cmd("srvN", "LPUSH %s %s", "INVITE2", "$var(json)", "r");
redis_free("r");
~~~

After that call forwards to termination node for processing.

#### Termination node

All calls cleaned with this simple function.

~~~python
def number_clean(number):
  match_pat = re.compile(r'\d*00([^0]\d{9}\d+)', flags=re.IGNORECASE)
  number = str(number)
  results = match_pat.match(number)
  if results == None:
    return number[-12:]
  return results.group(1)[-12:]

~~~

After that if call costs less than $0.02 per minute it forwards to Asterisk.

~~~asterisk
[honeypot]
exten => _XXXX.,1,Verbose(Got call to ${EXTEN})
exten => _XXXX.,n,Set(TIMEOUT(ABSOLUTE)=10)
exten => _XXXX.,n, Set(GROUP()=OUTBOUND_GROUP)
exten => _XXXX.,n, GotoIf($[${GROUP_COUNT()} > 1]?hangup)
exten => _XXXX.,n,Dial(SIP/outbount_trunk/${EXTEN})
exten => _XXXX.,n(hangup),Hangup()
~~~

## Results

I use 4 sensor nodes located in NL, DE, SG и NYC.

For 18 days, 254805 INVITE were collected from 296 different IP's. On average, 860 INVITE was received from IP.

#### Request sources
48% INVITE comes from single IP - 155.94.64.75.

Top 10 sources:

IP|Count|Percent
---|---|---
155.94.64.75|130917|51.38%
134.119.216.237|20502|8.05%
62.4.13.3|16507|6.48%
142.0.41.192|11429|4.49%
172.93.135.116|7755|3.04%
158.69.251.24|7553|2.96%
5.189.173.137|7374|2.89%
23.239.66.162|7191|2.82%
146.0.32.24|6815|2.67%
37.8.75.81|4404|1.73%

Most sources comes from hosting providers or from Palestine.

ASN|Count|Name
---|---|---
15975|96|PALTEL
12975|39|PALTEL
12876|25|ONLINE S.A.S
24961|18|MyLoc
19531|16|Nodes Direct
31408|14|Orange (Palestine)
16276|11|OVH
8972|10|PlusServer
42314|5|Fusion services (Palestine)
15169|5|Google cloud

#### Used UA

UA|Количество IP
---|---
eyeBeam release 3006o stamp 17551|90
sipcli/v1.8|90
eyeBeam release 3007n stamp 17816|32
friendly-scanner|31
eyeBeam release 3004t stamp 16741|21

![uas counts](https://raw.githubusercontent.com/UserAd/data_science/master/VoIP%20fraud/images/uas_distribution.png)


#### Test numbers

For every IP i get first number.
It turned out 209 numbers. Some of them were used more than once from different IP.

Destination|Attempts
---|---
972599935119|9
972597336687|7
972597449519|5
970595101118|5
441904911031|5
442033477777|4
46812410828|4
441200640008|4
14042605390|4
441299887220|4

Countries distribution looks like:

Country|Count
---|---
gb|121
il|55
us|20
se|17
pl|10
ps|9
eg|3
ch|3
ru|3
ee|2

![scan numbers](https://raw.githubusercontent.com/UserAd/data_science/master/VoIP%20fraud/images/scan_numbers.png)

Some calls 8.6% (22005) is used for scan local extensions (1-99999).

## Conclusion

If you block known UA (sipcli and friendly-scanner), you can filter out about 45% of attempts.

It can be achieved using this simple code:

~~~kamailio
if($ua =~ "(friendly-scanner|sipvicious|sipcli|VaxSIPUserAgent|voxalot)") {
  exit;
}
~~~

And you can block all calls to nonstandart destinations like Palestine.



