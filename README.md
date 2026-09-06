# RkStar64.sys (RockStar64.sys)

## Exclamation-mark
- The driver has not undergone stress-testing under the HLK, i will follow up with a result in the next few days, until then i do not classify this as Sign Ready.
- It currently supports both Windows 10 and the latest version of Windows 11.

## Question-mark
- This is a Hardware Uility Toolkit intended to be used for Diagnostics on an E-Guitar Visualization Component.
- It supports the following ioctl:
    #### GetBaseAddress | paramaters (in order) -> processName (single)
    #### ReadVirtualMemory | paramaters (in order) -> processId -> readTargetHex -> size (auto)
    #### WriteVirtualMemory | paramaters (in order) -> processId -> writeTargetHex -> writeValue (auto)
- A Video showing the Integration Tool (with the driver pre-loaded) — [Client Showcase.mp4](https://github.com/ioallocate/RkStar64/raw/main/Assets/Showcase.mp4)

## At
- Claude has been used to assist with writing the ReadWriteTarget.

## Dot
- This Diagnostics Driver is compatible and works on and with kernel level anti-cheats. This i can confirm because i personally tested it.
- Notice this is for educational purposes only, i do not condone nor encourage missuse of this driver.
