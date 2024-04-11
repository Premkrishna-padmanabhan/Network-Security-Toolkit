import customtkinter as ctk
import socket

import banner_grabber, nmapscan, geoip, wifiscanner, packet_sniffer


def nmap():

    try:

        ans.configure(text="Scanning ports...\n\n")
        get = ctk.CTkInputDialog(text="Enter a domain: ", title="Nmap Scanner")
        target = socket.gethostbyname(get.get_input())
        out = nmapscan.scan(target)
        ans.configure(text=out + "\n\n")
    except Exception as e:
        ans.configure(text=e)

def banner_grab():
    window = ctk.CTkToplevel(app)
    window.title("Banner Grabber")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.configure(text="Grabbing banner...\n\n")
            get0 = ctk.CTkInputDialog(text="Enter a url: ", title="Banner Grabber")
            url = socket.gethostbyname(get0.get_input())
            get1 = ctk.CTkInputDialog(text="Enter a port: ", title="Banner Grabber")
            port = get1.get_input()
            out = banner_grabber.banner_grabber(url, int(port))
            ans.configure(text=out + "\n\n")
        except Exception as e:
            ans.configure(text="Enter a valid url and port.\n\n")

    def ipaddr():
        try:
            ans.configure(text="Grabbing banner...\n\n")
            get0 = ctk.CTkInputDialog(text="Enter an IP: ", title="Banner Grabber")
            ip = get0.get_input()
            get1 = ctk.CTkInputDialog(text="Enter a port: ", title="Banner Grabber")
            port = get1.get_input()
            out = banner_grabber.banner_grabber(ip, int(port))
            ans.configure(text=out + "\n\n")
        except Exception as e:
            ans.configure(text="Enter a valid ip and port.\n\n")

    dom = ctk.CTkButton(window, text="Enter a domain: ", command=domain)
    dom.place(x=150, y=100, anchor="center")
    ip = ctk.CTkButton(window, text="Enter an IP: ", command=ipaddr)
    ip.place(x=150, y=150, anchor="center")


def locate():

        try:
            ans.configure(text="Locating...\n\n")
            get = ctk.CTkInputDialog(text="Enter a url: ", title="GeoIP")
            url = get.get_input()
            ans.configure(text="Locating...\n\n")
            out = geoip.get_loc(url)
            ans.configure(text=out + "\n\n")

        except Exception as e:
            ans.configure(text="Please enter a valid url.\n\n")




def wifiscan():
    window = ctk.CTkToplevel(app)
    window.title("Wifi Scanner")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.configure(text="Scanning...\n\n")
            out = wifiscanner.wifi(range.get())
            ans.configure(text=out + "\n\n")
        except Exception as e:
            ans.configure(text="Please enter a valid ip range.\n\n")

    iplabel = ctk.CTkLabel(window, text="Enter a ip range: ")
    iplabel.place(x=150, y=50, anchor="center")
    range = ctk.CTkEntry(window, placeholder_text="192.168.155.0/24", width=200)
    range.place(x=150, y=100, anchor="center")
    dom = ctk.CTkButton(window, text="Wifi Scanner", command=domain)
    dom.place(x=150, y=150, anchor="center")


def sniff():
    window = ctk.CTkToplevel(app)
    window.title("Packet Sniffer")
    window.geometry("300x250")
    window.resizable(False, False)

    def domain():
        try:
            ans.configure("Sniffing...\n\n")
            out = packet_sniffer.packet(int(count.get()))
            ans.configure(text=out + "\n\n")
        except Exception as e:
            ans.configure(text="Please enter a valid number.\n\n")

    countlabel = ctk.CTkLabel(window, text="Enter the number of packets to be sniffed: ")
    countlabel.place(x=150, y=50, anchor="center")
    count = ctk.CTkEntry(window, placeholder_text="Enter a number", width=200)
    count.place(x=150, y=100, anchor="center")
    dom = ctk.CTkButton(window, text="Packet Sniffer", command=domain)
    dom.place(x=150, y=150, anchor="center")


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("marsh.json")

app = ctk.CTk()
app.geometry("750x800")
app.resizable(False, False)

app.title("NS Toolkit")

title = ctk.CTkLabel(app, text="AVAILABLE FUNCTIONS: ", font=("Baskerville Old Face", 20))
title.place(x=375, y=100, anchor="center")

nmaps = ctk.CTkButton(app, text="Nmap Scan".upper(), command=nmap)
nmaps.place(x=250, y=150, anchor="center")

ban = ctk.CTkButton(app, text="Banner Grabber".upper(), command=banner_grab)
ban.place(x=250, y=200, anchor="center")

geo = ctk.CTkButton(app, text="Geolocation".upper(), command=locate)
geo.place(x=480, y=150, anchor="center")

wifi = ctk.CTkButton(app, text="Wifi Scanner".upper(), command=wifiscan)
wifi.place(x=480, y=200, anchor="center")

sni = ctk.CTkButton(app, text="Packet Sniffer".upper(), command=sniff)
sni.place(x=250, y=250, anchor="center")

bruh = ctk.CTkButton(app, text="")
bruh.place(x=480, y=250, anchor="center")

output = ctk.CTkLabel(app, text="Output: ".upper(), font=("Century Gothic", 20))
output.place(x=375, y=340, anchor="center")

ans = ctk.CTkLabel(app, text="", width=600, height=300 )
ans.place(x=375, y=560, anchor="center")

quit = ctk.CTkButton(app, text="Quit", command=app.quit)
quit.place(x=375, y=700, anchor="center")

app.mainloop()
