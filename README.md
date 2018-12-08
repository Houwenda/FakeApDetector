# FakeApDetector
a script tool to help recognizing evil twin attack 
## Main Theory:
#### 1.Check for APs that are set up using certain wireless interface cards.
#### 2.Detect whether there is a wireless interface card is sending beacon frames using fake MAC address by comparing the beacon frames from the same AP MAC address.
#### 3.Use timestamp to tell fake APs from authenticated ones.

## To be done:
#### 1.Using server to detect fake APs to support more platforms.
#### 2.Detection based on timestamp is not reliable due to defect of algorithms, which needs improvement.
