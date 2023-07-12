https://tryhackme.com/room/introdigitalforensics

#  Practical Example of Digital Forensics

> Everything we do on our digital devices, from smartphones to computers, leaves traces. Let’s see how we can use this in the subsequent investigation

```bash
exiftool letter-image.jpg | grep gps -i
```

**My solution is:**

1.  Convert DMS (degrees, minutes, seconds) to DD (decimal degrees) using [https://gps-coordinates.org/](https://gps-coordinates.org/)[](https://gps-coordinates.org/)
2.  Search the converted DD on google map : 51.51441666666667 -0.09409166666666666
3.  Get Street Name : `Milk Street`