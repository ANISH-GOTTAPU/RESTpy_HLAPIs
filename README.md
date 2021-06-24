# Required python packages
pip install netaddr

# Import the packages
*from ixia_restpy_apis import Ixia*

# Run script
Pass API Server IP and if you are going to create new config send clearConfig as True else False.

*tgnObj = Ixia('10.39.71.172', clearConfig=True)*

*tgnObj.connect_to_session(sessionId=1)  # To connect the Session.*

For more test cases please check the test file.

# Supported Server Versions
Linux IxNetwork API Server

Windows IxNetwork GUI

Windows IxNetwork Connection Manager
