# ArtNet Advertise Nanoleaf

This little project allows you to use your Nanoleaf panels with ArtNet. Each panel can be changed individually via DMX controls.

I am using [SoundSwitch](https://www.soundswitch.com/) for my usecase. The nanoleafapi module is there because the PR is not merged yet which activates the extControl mode.

This is all based on the works of lightguru Domas (@dzelionis / https://www.linkedin.com/in/dzelionis) !

# Requirements

- requests
- sseclient

etc

# Configuration

```
UDP_IP = "192.168.52.55" # This is the IP of your device
BROADCAST_IP = "192.168.52.255" # This is the broadcast address 
NANOLEAF_IP = "192.168.52.56" # This is the IP of your nanoleaf
```

# Known bugs

- lag of 1 bar.

# Todo

- Write documentation
