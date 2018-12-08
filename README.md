# FakeApDetector
a script tool to help recognizing evil twin attack 
## Main Theory:
#### 1.Check for APs that are set up using certain wireless interface cards.
#### 2.Detect whether there is a wireless interface card is sending beacon frames using fake MAC address by comparing the beacon frames from the same AP MAC address.
#### 3.Use timestamp to tell fake APs from authenticated ones.

## Some Screenshots:
![image](https://github.com/Houwenda/FakeApDetector/raw/master/examples/1.png)
![image](https://github.com/Houwenda/FakeApDetector/raw/master/examples/2.png)
![image](https://github.com/Houwenda/FakeApDetector/raw/master/examples/3.png)
![image](https://github.com/Houwenda/FakeApDetector/raw/master/examples/4.png)

## To be done:
#### 1.Using server detection in order to support multiple platforms(currently this tool can only run on Linux).
#### 2.Detection based on timestamp is not reliable due to defect of algorithms, which needs improvement.
