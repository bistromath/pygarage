import automationhat, time

RELAY = 1

def toggle_garage_door():
    automationhat.relay[RELAY-1].write(True)
    time.sleep(0.2)
    automationhat.relay[RELAY-1].write(False)

def set_connected_light(state):
    automationhat.light.comms.write(int(state))

def set_power_light(state):
    automationhat.light.power.write(int(state))
