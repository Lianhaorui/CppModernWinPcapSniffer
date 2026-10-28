#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <uxtheme.h>
#include <commctrl.h>
#include <commdlg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <mutex>
#include <cmath>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")

#define WM_PACKET WM_APP + 1
#define WM_STATUS WM_APP + 2
#define WM_CAPTURE_STOPPED WM_APP + 3

#define IDI_APPICON 101

#define APP_BG RGB(242, 242, 247)
#define CARD_BG RGB(255, 255, 255)
#define BORDER_RGB RGB(229, 229, 234)
#define TEXT_PRIMARY RGB(28, 28, 30)
#define TEXT_SECONDARY RGB(110, 110, 115)
#define ACCENT RGB(0, 122, 255)
#define SUCCESS RGB(52, 199, 89)
#define DANGER RGB(255, 59, 48)
#define WARNING RGB(255, 149, 0)
#define PURPLE RGB(88, 86, 214)
#define TEAL RGB(32, 148, 139)

struct PacketRecord {
    unsigned long long no;
    SYSTEMTIME time;
    std::string src;
    std::string dst;
    std::string proto;
    std::string info;
    unsigned long len;
    unsigned int ts_sec;
    unsigned int ts_usec;
    std::vector<unsigned char> data;
};

struct AdapterInfo {
    std::wstring name;
    std::wstring desc;
};

struct CaptureGlobals {
    HINSTANCE hInst;
    HWND mainWnd;
    HWND adapterCombo;
    HWND filterEdit;
    HWND startBtn;
    HWND stopBtn;
    HWND clearBtn;
    HWND applyBtn;
    HWND promiscBtn;
    HWND packetList;
    HWND detailTree;
    HWND hexEdit;
    HWND statusBar;
    std::vector<AdapterInfo> adapters;
    std::vector<PacketRecord*> packets;
    std::map<std::wstring, unsigned long> protoCount;
    std::map<std::wstring, unsigned long long> protoBytes;
    std::map<std::wstring, unsigned long> endpointCount;
    std::map<std::wstring, unsigned long long> endpointBytes;
    std::wstring statusText;
    std::mutex pktMutex;
    std::thread captureThread;
    void* pcapHandle;
    volatile bool running;
    bool promiscuous = true;
    unsigned long long nextNo;
    unsigned long long totalPackets;
    unsigned long long totalBytes;
    CRITICAL_SECTION cs;
    bool materialEnabled;
};

static CaptureGlobals g;
static int g_dpi = 96;

static int S(int value) {
    return MulDiv(value, g_dpi, 96);
}

typedef struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    struct pcap_addr* addresses;
    unsigned int flags;
} pcap_if_t;

typedef struct pcap_addr_s {
    struct pcap_addr_s* next;
    sockaddr* addr;
    sockaddr* netmask;
    sockaddr* broadaddr;
    sockaddr* dstaddr;
} pcap_addr_t;

typedef struct pcap_pkthdr {
    struct timeval ts;
    unsigned int caplen;
    unsigned int len;
} pcap_pkthdr;

typedef struct bpf_program {
    unsigned int bf_len;
    void* bf_insns;
} bpf_program;

typedef void pcap_t;

typedef void (*pcap_handler)(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);

typedef int (*PCAP_FINDALLDEVS)(pcap_if_t**, char*);
typedef void (*PCAP_FREEALLDEVS)(pcap_if_t*);
typedef pcap_t* (*PCAP_OPEN_LIVE)(const char*, int, int, int, char*);
typedef int (*PCAP_COMPILE)(pcap_t*, bpf_program*, const char*, int, unsigned int);
typedef int (*PCAP_SETFILTER)(pcap_t*, bpf_program*);
typedef int (*PCAP_LOOP)(pcap_t*, int, pcap_handler, unsigned char*);
typedef void (*PCAP_BREAKLOOP)(pcap_t*);
typedef void (*PCAP_CLOSE)(pcap_t*);
typedef const char* (*PCAP_LIB_VERSION)();
typedef char* (*PCAP_GETERR)(pcap_t*);

static PCAP_FINDALLDEVS p_pcap_findalldevs;
static PCAP_FREEALLDEVS p_pcap_freealldevs;
static PCAP_OPEN_LIVE p_pcap_open_live;
static PCAP_COMPILE p_pcap_compile;
static PCAP_SETFILTER p_pcap_setfilter;
static PCAP_LOOP p_pcap_loop;
static PCAP_BREAKLOOP p_pcap_breakloop;
static PCAP_CLOSE p_pcap_close;
static PCAP_LIB_VERSION p_pcap_lib_version;
static PCAP_GETERR p_pcap_geterr;
static HMODULE pcapDll = NULL;

static bool LoadWinPcapAPI() {
    SetDllDirectoryW(L"C:\\Windows\\System32\\Npcap");
    const wchar_t* paths[] = { L"C:\\Windows\\System32\\Npcap\\wpcap.dll", L"wpcap.dll" };
    for (const wchar_t* p : paths) {
        pcapDll = LoadLibraryW(p);
        if (pcapDll) break;
    }
    if (!pcapDll) return false;
    p_pcap_findalldevs = (PCAP_FINDALLDEVS)GetProcAddress(pcapDll, "pcap_findalldevs");
    p_pcap_freealldevs = (PCAP_FREEALLDEVS)GetProcAddress(pcapDll, "pcap_freealldevs");
    p_pcap_open_live = (PCAP_OPEN_LIVE)GetProcAddress(pcapDll, "pcap_open_live");
    p_pcap_compile = (PCAP_COMPILE)GetProcAddress(pcapDll, "pcap_compile");
    p_pcap_setfilter = (PCAP_SETFILTER)GetProcAddress(pcapDll, "pcap_setfilter");
    p_pcap_loop = (PCAP_LOOP)GetProcAddress(pcapDll, "pcap_loop");
    p_pcap_breakloop = (PCAP_BREAKLOOP)GetProcAddress(pcapDll, "pcap_breakloop");
    p_pcap_close = (PCAP_CLOSE)GetProcAddress(pcapDll, "pcap_close");
    p_pcap_lib_version = (PCAP_LIB_VERSION)GetProcAddress(pcapDll, "pcap_lib_version");
    p_pcap_geterr = (PCAP_GETERR)GetProcAddress(pcapDll, "pcap_geterr");
    return p_pcap_findalldevs && p_pcap_freealldevs && p_pcap_open_live && p_pcap_compile && p_pcap_setfilter && p_pcap_loop && p_pcap_breakloop && p_pcap_close;
}

static std::wstring ToW(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring SanitizeWide(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t ch : s) {
        if ((ch < 32 && ch != L'\t' && ch != L'\n' && ch != L'\r') || ch == 0x7F) {
            out.push_back(L' ');
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

static std::string ToA(const std::wstring& s) {
    if (s.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0, NULL, NULL);
    std::string a(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &a[0], n, NULL, NULL);
    return a;
}

static std::string IPToString(const unsigned char* b) {
    std::ostringstream os;
    os << (int)b[0] << '.' << (int)b[1] << '.' << (int)b[2] << '.' << (int)b[3];
    return os.str();
}

static std::string MACToString(const unsigned char* b) {
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::setw(2) << (int)b[0] << ':'
       << std::setw(2) << (int)b[1] << ':' << std::setw(2) << (int)b[2] << ':'
       << std::setw(2) << (int)b[3] << ':' << std::setw(2) << (int)b[4] << ':'
       << std::setw(2) << (int)b[5];
    return os.str();
}

static std::string HexDump(const std::vector<unsigned char>& d) {
    std::ostringstream os;
    for (size_t i = 0; i < d.size(); i += 16) {
        os << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < d.size()) os << std::hex << std::setw(2) << std::setfill('0') << (int)d[i + j] << ' ';
            else os << "   ";
        }
        os << ' ';
        for (size_t j = 0; j < 16 && i + j < d.size(); ++j) {
            unsigned char c = d[i + j];
            os << (c >= 32 && c < 127 ? (char)c : '.');
        }
        os << '\n';
    }
    return os.str();
}

static void AddTreeItem(HWND tree, HTREEITEM parent, const std::wstring& text) {
    TVINSERTSTRUCTW tv = {};
    tv.item.mask = TVIF_TEXT;
    tv.item.pszText = (LPWSTR)text.c_str();
    tv.hInsertAfter = TVI_LAST;
    tv.hParent = parent;
    TreeView_InsertItem(tree, &tv);
}

static std::string ExtractLine(const unsigned char* data, size_t size, size_t& pos) {
    size_t start = pos;
    while (pos < size) {
        if (data[pos] == '\r' || data[pos] == '\n') {
            std::string line(reinterpret_cast<const char*>(data + start), pos - start);
            if (pos + 1 < size && data[pos] == '\r' && data[pos + 1] == '\n') pos += 2;
            else pos += 1;
            return line;
        }
        ++pos;
    }
    return std::string(reinterpret_cast<const char*>(data + start), size - start);
}

static std::string CleanAscii(const unsigned char* data, size_t size) {
    std::ostringstream out;
    for (size_t i = 0; i < size; ++i) {
        unsigned char c = data[i];
        out << ((c >= 32 && c < 127) ? (char)c : '.');
    }
    return out.str();
}

static std::string ParseHttpInfo(const unsigned char* payload, size_t len, unsigned short sport, unsigned short dport) {
    std::ostringstream info;
    bool isRequest = (payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' || payload[0] == 'D' || payload[0] == 'C' || payload[0] == 'O');
    size_t pos = 0;
    std::string first = ExtractLine(payload, len, pos);
    if (isRequest) {
        std::istringstream line(first);
        std::string method, path, version;
        line >> method >> path >> version;
        info << method << " " << path << " " << version;
    } else {
        std::istringstream line(first);
        std::string version, code, reason;
        line >> version >> code;
        std::getline(line, reason);
        info << version << " " << code << reason;
    }
    std::string host;
    while (pos < len) {
        std::string header = ExtractLine(payload, len, pos);
        if (header.empty()) break;
        if (header.length() > 5 && (_strnicmp(header.c_str(), "Host:", 5) == 0)) {
            host = header.substr(5);
            if (!host.empty() && host[0] == ' ') host.erase(host.begin());
        }
    }
    info << (host.empty() ? "" : " Host=") << host;
    return info.str();
}

static std::string ParseDnsName(const unsigned char* data, size_t size, size_t& offset) {
    std::ostringstream name;
    unsigned char hops = 0;
    while (offset < size && hops < 32) {
        unsigned char n = data[offset++];
        if (n == 0) break;
        if ((n & 0xC0) == 0xC0) {
            if (offset < size) offset++;
            break;
        }
        if (n > 63) break;
        if (offset + n > size) break;
        if (name.tellp() > 0) name << ".";
        for (unsigned char i = 0; i < n; ++i) {
            unsigned char c = data[offset++];
            name << ((c >= 32 && c < 127) ? (char)c : '.');
        }
        ++hops;
    }
    return name.str();
}

static void PacketHandler(unsigned char* user, const struct pcap_pkthdr* hdr, const unsigned char* pkt) {
    PacketRecord* rec = new PacketRecord();
    rec->no = 0;
    GetLocalTime(&rec->time);
    rec->ts_sec = (unsigned int)hdr->ts.tv_sec;
    rec->ts_usec = (unsigned int)hdr->ts.tv_usec;
    rec->len = hdr->len;
    rec->data.assign(pkt, pkt + hdr->caplen);
    if (hdr->caplen >= 14) {
        unsigned short ethType = (pkt[12] << 8) | pkt[13];
        if (ethType == 0x0806 && hdr->caplen >= 42) {
            rec->proto = "ARP";
            unsigned short op = (pkt[20] << 8) | pkt[21];
            std::ostringstream os;
            std::string senderMac = MACToString(pkt + 22);
            std::string senderIp = IPToString(pkt + 28);
            std::string targetIp = IPToString(pkt + 38);
            os << (op == 1 ? "Who has " + targetIp + "? Tell " + senderIp : senderIp + " is at " + senderMac);
            rec->info = os.str();
            rec->src = MACToString(pkt + 6);
            rec->dst = MACToString(pkt);
        } else if (ethType == 0x0800 && hdr->caplen >= 34) {
            const unsigned char* ip = pkt + 14;
            unsigned char ihl = (ip[0] & 0x0F) * 4;
            unsigned char proto = ip[9];
            unsigned short totalLen = (ip[2] << 8) | ip[3];
            rec->src = IPToString(ip + 12);
            rec->dst = IPToString(ip + 16);
            if (proto == 1 && hdr->caplen >= 14 + ihl + 4) {
                rec->proto = "ICMP";
                unsigned char type = ip[ihl], code = ip[ihl + 1];
                std::ostringstream os;
                os << "Type=" << (int)type << " Code=" << (int)code << " Id=" << ((ip[ihl+4]<<8)|ip[ihl+5]);
                rec->info = os.str();
            } else if (proto == 2 && hdr->caplen >= 14 + ihl + 8) {
                rec->proto = "IGMP";
                unsigned char type = ip[ihl];
                std::ostringstream os;
                os << "Type=" << (int)type << " Group=" << IPToString(ip + ihl + 4);
                rec->info = os.str();
            } else if (proto == 6 && hdr->caplen >= 14 + ihl + 20) {
                const unsigned char* t = ip + ihl;
                unsigned short sport = (t[0] << 8) | t[1], dport = (t[2] << 8) | t[3];
                unsigned int seq = (t[4] << 24) | (t[5] << 16) | (t[6] << 8) | t[7];
                unsigned int ack = (t[8] << 24) | (t[9] << 16) | (t[10] << 8) | t[11];
                unsigned char flags = t[13];
                unsigned int headerLen = ((t[12] >> 4) & 0xF) * 4;
                size_t payloadOffset = 14 + ihl + headerLen;
                size_t payloadLen = (payloadOffset < hdr->caplen) ? (hdr->caplen - payloadOffset) : 0;
                std::ostringstream os;
                os << sport << " -> " << dport << " Seq=" << seq << " Ack=" << ack << " Flags=0x" << std::hex << (int)flags;
                if (payloadLen > 0) {
                    const unsigned char* payload = pkt + payloadOffset;
                    bool http = (sport == 80 || dport == 80 || sport == 8080 || dport == 8080) &&
                                payloadLen >= 4 &&
                                (payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' ||
                                 payload[0] == 'D' || payload[0] == 'C' || payload[0] == 'O' ||
                                 (payloadLen >= 5 && strncmp(reinterpret_cast<const char*>(payload), "HTTP/", 5) == 0));
                    if (http) {
                        rec->proto = "HTTP";
                        os << " | " << ParseHttpInfo(payload, payloadLen, sport, dport);
                    } else if ((sport == 443 || dport == 443 || sport == 8443 || dport == 8443) && payloadLen >= 3 && payload[0] == 0x16) {
                        rec->proto = "TLS";
                        os << " | TLS Record";
                    } else if (sport == 53 || dport == 53) {
                        rec->proto = "DNS";
                        size_t offset = 12;
                        if (payloadLen >= 12) {
                            std::string qname = ParseDnsName(payload, payloadLen - 12 >= 0 ? payloadLen : 0, offset);
                            os << " | DNS " << qname;
                        }
                    } else {
                        rec->proto = "TCP";
                    }
                } else {
                    rec->proto = "TCP";
                }
                rec->info = os.str();
            } else if (proto == 17 && hdr->caplen >= 14 + ihl + 8) {
                const unsigned char* u = ip + ihl;
                unsigned short sport = (u[0] << 8) | u[1], dport = (u[2] << 8) | u[3];
                std::ostringstream os;
                os << sport << " -> " << dport;
                size_t payloadOffset = 14 + ihl + 8;
                size_t payloadLen = (payloadOffset < hdr->caplen) ? (hdr->caplen - payloadOffset) : 0;
                if (sport == 53 || dport == 53) {
                    rec->proto = "DNS";
                    if (payloadLen >= 12) {
                        size_t offset = 12;
                        os << " | DNS " << ParseDnsName(pkt + payloadOffset, payloadLen, offset);
                    }
                } else if (sport == 67 || sport == 68 || dport == 67 || dport == 68) {
                    rec->proto = "DHCP";
                    os << " | DHCP";
                } else {
                    rec->proto = "UDP";
                }
                rec->info = os.str();
            } else {
                rec->proto = "IPv4";
                std::ostringstream os;
                os << "Proto=" << (int)proto << " Len=" << totalLen;
                rec->info = os.str();
            }
        } else {
            rec->proto = "Ethernet";
            rec->src = MACToString(pkt + 6);
            rec->dst = MACToString(pkt);
            std::ostringstream os;
            os << "Type=0x" << std::hex << ethType;
            rec->info = os.str();
        }
    } else {
        rec->proto = "Raw";
        rec->info = "Short frame";
    }
    PostMessageW(g.mainWnd, WM_PACKET, 0, (LPARAM)rec);
}

static DWORD WINAPI CaptureThread(LPVOID param) {
    char errbuf[256] = {0};
    int sel = (int)SendMessageW(g.adapterCombo, CB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)g.adapters.size()) return 1;
    std::string dev = ToA(g.adapters[sel].name);
    g.pcapHandle = p_pcap_open_live(dev.c_str(), 65535, g.promiscuous ? 1 : 0, 1000, errbuf);
    if (!g.pcapHandle) {
        g.running = false;
        MessageBoxW(g.mainWnd, L"打开网卡失败", L"错误", MB_ICONERROR);
        PostMessageW(g.mainWnd, WM_STATUS, 0, (LPARAM)new std::wstring(L"就绪"));
        PostMessageW(g.mainWnd, WM_CAPTURE_STOPPED, 0, 0);
        return 1;
    }
    wchar_t fbuf[512] = {0};
    GetWindowTextW(g.filterEdit, fbuf, 512);
    std::string filter = ToA(fbuf);
    if (!filter.empty()) {
        bpf_program fp = {};
        unsigned int netmask = 0xFFFFFF00;
        if (p_pcap_compile(g.pcapHandle, &fp, filter.c_str(), 1, netmask) == -1) {
            g.running = false;
            MessageBoxW(g.mainWnd, L"过滤器语法错误", L"错误", MB_ICONERROR);
            p_pcap_close(g.pcapHandle); g.pcapHandle = NULL;
            PostMessageW(g.mainWnd, WM_STATUS, 0, (LPARAM)new std::wstring(L"就绪"));
            PostMessageW(g.mainWnd, WM_CAPTURE_STOPPED, 0, 0);
            return 1;
        }
        p_pcap_setfilter(g.pcapHandle, &fp);
    }
    PostMessageW(g.mainWnd, WM_STATUS, 0, (LPARAM)new std::wstring(L"正在捕获..."));
    p_pcap_loop(g.pcapHandle, -1, PacketHandler, NULL);
    if (g.pcapHandle) { p_pcap_close(g.pcapHandle); g.pcapHandle = NULL; }
    g.running = false;
    PostMessageW(g.mainWnd, WM_STATUS, 0, (LPARAM)new std::wstring(L"已停止"));
    PostMessageW(g.mainWnd, WM_CAPTURE_STOPPED, 0, 0);
    return 0;
}

static void UpdateStatusBar() {
    wchar_t text[256];
    swprintf_s(text, 256, L"包: %llu  字节: %llu  TCP: %lu  UDP: %lu  ARP: %lu  ICMP: %lu  IGMP: %lu", g.totalPackets, g.totalBytes, g.protoCount[L"TCP"], g.protoCount[L"UDP"], g.protoCount[L"ARP"], g.protoCount[L"ICMP"], g.protoCount[L"IGMP"]);
    g.statusText = text;
    SendMessageW(g.statusBar, SB_SETTEXTW, 0, (LPARAM)g.statusText.c_str());
}

static void InsertPacket(PacketRecord* rec) {
    EnterCriticalSection(&g.cs);
    rec->no = ++g.nextNo;
    g.packets.push_back(rec);
    if (g.packets.size() > 5000) {
        PacketRecord* old = g.packets.front();
        g.packets.erase(g.packets.begin());
        delete old;
        ListView_DeleteItem(g.packetList, 0);
    }
    g.totalPackets++;
    g.totalBytes += rec->len;
    std::wstring proto = ToW(rec->proto);
    g.protoCount[ToW(rec->proto)]++;
    g.protoBytes[ToW(rec->proto)] += rec->len;
    std::wstring ep1 = ToW(rec->src), ep2 = ToW(rec->dst);
    g.endpointCount[ep1]++; g.endpointBytes[ep1] += rec->len;
    g.endpointCount[ep2]++; g.endpointBytes[ep2] += rec->len;
    LeaveCriticalSection(&g.cs);

    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = ListView_GetItemCount(g.packetList);
    wchar_t buf[64];
    swprintf_s(buf, 64, L"%llu", rec->no);
    lvi.pszText = buf;
    lvi.lParam = (LPARAM)rec;
    int idx = ListView_InsertItem(g.packetList, &lvi);
    std::wstring srcText = SanitizeWide(ToW(rec->src));
    std::wstring dstText = SanitizeWide(ToW(rec->dst));
    std::wstring protoText = SanitizeWide(ToW(rec->proto));
    std::wstring infoText = SanitizeWide(ToW(rec->info));
    wchar_t time[64];
    swprintf_s(time, 64, L"%02d:%02d:%02d.%03d", rec->time.wHour, rec->time.wMinute, rec->time.wSecond, rec->time.wMilliseconds);
    ListView_SetItemText(g.packetList, idx, 1, time);
    ListView_SetItemText(g.packetList, idx, 2, (LPWSTR)srcText.c_str());
    ListView_SetItemText(g.packetList, idx, 3, (LPWSTR)dstText.c_str());
    ListView_SetItemText(g.packetList, idx, 4, (LPWSTR)protoText.c_str());
    wchar_t len[32]; swprintf_s(len, 32, L"%lu", rec->len);
    ListView_SetItemText(g.packetList, idx, 5, len);
    ListView_SetItemText(g.packetList, idx, 6, (LPWSTR)infoText.c_str());
    UpdateStatusBar();
}

static void ShowDetails(int idx) {
    TreeView_DeleteAllItems(g.detailTree);
    SetWindowTextW(g.hexEdit, L"");
    if (idx < 0 || idx >= (int)g.packets.size()) return;
    PacketRecord* rec = g.packets[idx];
    HTREEITEM root = NULL;
    TVINSERTSTRUCTW tv = {};
    tv.item.mask = TVIF_TEXT;
    std::wstring title = L"第 " + std::to_wstring(rec->no) + L" 个数据包";
    tv.item.pszText = (LPWSTR)title.c_str();
    tv.hInsertAfter = TVI_ROOT;
    root = TreeView_InsertItem(g.detailTree, &tv);
    AddTreeItem(g.detailTree, root, L"时间: " + std::to_wstring(rec->time.wHour) + L":" + std::to_wstring(rec->time.wMinute) + L":" + std::to_wstring(rec->time.wSecond) + L"." + std::to_wstring(rec->time.wMilliseconds));
    AddTreeItem(g.detailTree, root, L"源地址: " + SanitizeWide(ToW(rec->src)));
    AddTreeItem(g.detailTree, root, L"目的地址: " + SanitizeWide(ToW(rec->dst)));
    AddTreeItem(g.detailTree, root, L"协议: " + SanitizeWide(ToW(rec->proto)));
    AddTreeItem(g.detailTree, root, L"长度: " + std::to_wstring(rec->len) + L" 字节");
    AddTreeItem(g.detailTree, root, L"摘要: " + SanitizeWide(ToW(rec->info)));
    AddTreeItem(g.detailTree, root, L"十六进制内容:\n" + ToW(HexDump(rec->data)));
    SetWindowTextW(g.hexEdit, ToW(HexDump(rec->data)).c_str());
}

static void ClearPackets() {
    EnterCriticalSection(&g.cs);
    for (auto* p : g.packets) delete p;
    g.packets.clear();
    g.protoCount.clear(); g.protoBytes.clear(); g.endpointCount.clear(); g.endpointBytes.clear();
    g.nextNo = 0; g.totalPackets = 0; g.totalBytes = 0;
    LeaveCriticalSection(&g.cs);
    ListView_DeleteAllItems(g.packetList);
    TreeView_DeleteAllItems(g.detailTree);
    UpdateStatusBar();
}

static void ShowStatsWindow(HWND parent) {
    struct StatsData { std::wstring proto; unsigned long packets; unsigned long long bytes; };
    std::vector<StatsData> rows;
    EnterCriticalSection(&g.cs);
    for (auto& p : g.protoCount) rows.push_back({ p.first, p.second, g.protoBytes[p.first] });
    LeaveCriticalSection(&g.cs);
    std::sort(rows.begin(), rows.end(), [](const StatsData& a, const StatsData& b) { return a.packets > b.packets; });
    std::wostringstream os;
    os << L"协议统计\n";
    for (auto& r : rows) os << r.proto << L"\t" << r.packets << L" 包\t" << r.bytes << L" 字节\n";
    MessageBoxW(parent, os.str().c_str(), L"捕获统计", MB_OK | MB_ICONINFORMATION);
}

static void ResetCaptureButtons(HWND hwnd) {
    EnableWindow(g.startBtn, TRUE);
    EnableWindow(g.stopBtn, FALSE);
}

static void StopCapture(HWND hwnd) {
    if (g.running) {
        g.running = false;
        if (g.pcapHandle && p_pcap_breakloop) p_pcap_breakloop(g.pcapHandle);
    }
    if (g.captureThread.joinable()) g.captureThread.join();
    MSG stale;
    while (PeekMessageW(&stale, hwnd, WM_CAPTURE_STOPPED, WM_CAPTURE_STOPPED, PM_REMOVE)) {}
    ResetCaptureButtons(hwnd);
}

static void StartCapture(HWND hwnd) {
    StopCapture(hwnd);
    int sel = (int)SendMessageW(g.adapterCombo, CB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)g.adapters.size()) {
        MessageBoxW(hwnd, L"请先选择网卡", L"提示", MB_ICONINFORMATION);
        return;
    }
    g.running = true;
    EnableWindow(g.startBtn, FALSE);
    EnableWindow(g.stopBtn, TRUE);
    g.captureThread = std::thread(CaptureThread, nullptr);
}

static void ApplyFilterNow(HWND hwnd) {
    bool wasRunning = g.running;
    if (wasRunning) {
        StopCapture(hwnd);
        StartCapture(hwnd);
    }
}

static void SetFilterText(HWND hwnd, const wchar_t* text) {
    if (g.filterEdit) SetWindowTextW(g.filterEdit, text);
    bool wasRunning = g.running;
    if (wasRunning) ApplyFilterNow(hwnd);
}

static bool PickSaveFile(HWND owner, wchar_t* path, DWORD pathLen, const wchar_t* filter, const wchar_t* defExt) {
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = pathLen;
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    return GetSaveFileNameW(&ofn) != FALSE;
}

static bool PickOpenFile(HWND owner, wchar_t* path, DWORD pathLen, const wchar_t* filter) {
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = pathLen;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    return GetOpenFileNameW(&ofn) != FALSE;
}

static void SavePacketsPcap(HWND hwnd) {
    if (g.packets.empty()) {
        MessageBoxW(hwnd, L"当前没有可保存的数据包", L"提示", MB_ICONINFORMATION);
        return;
    }
    wchar_t path[MAX_PATH] = {0};
    if (!PickSaveFile(hwnd, path, MAX_PATH, L"PCAP 文件 (*.pcap)\0*.pcap\0所有文件 (*.*)\0*.*\0", L"pcap")) return;
    EnterCriticalSection(&g.cs);
    FILE* f = _wfopen(path, L"wb");
    if (!f) {
        LeaveCriticalSection(&g.cs);
        MessageBoxW(hwnd, L"无法创建文件", L"错误", MB_ICONERROR);
        return;
    }
    auto put16 = [&](unsigned short v) { fputc((int)(v & 0xff), f); fputc((int)((v >> 8) & 0xff), f); };
    auto put32 = [&](unsigned int v) { fputc((int)(v & 0xff), f); fputc((int)((v >> 8) & 0xff), f); fputc((int)((v >> 16) & 0xff), f); fputc((int)((v >> 24) & 0xff), f); };
    put32(0xa1b2c3d4);
    put16(2); put16(4); put32(0); put32(0); put32(65535); put32(1);
    for (PacketRecord* rec : g.packets) {
        unsigned int caplen = (unsigned int)rec->data.size();
        put32(rec->ts_sec);
        put32(rec->ts_usec);
        put32(caplen);
        put32(rec->len);
        fwrite(rec->data.data(), 1, caplen, f);
    }
    fclose(f);
    LeaveCriticalSection(&g.cs);
    std::wstring msg = L"已保存 " + std::to_wstring((unsigned long long)g.packets.size()) + L" 个数据包到:\n" + std::wstring(path);
    MessageBoxW(hwnd, msg.c_str(), L"保存成功", MB_OK | MB_ICONINFORMATION);
}

static void LoadPacketsPcap(HWND hwnd) {
    wchar_t path[MAX_PATH] = {0};
    if (!PickOpenFile(hwnd, path, MAX_PATH, L"PCAP 文件 (*.pcap;*.cap;*.pcapng)\0*.pcap;*.cap;*.pcapng\0所有文件 (*.*)\0*.*\0")) return;
    FILE* f = _wfopen(path, L"rb");
    if (!f) {
        MessageBoxW(hwnd, L"无法打开文件", L"错误", MB_ICONERROR);
        return;
    }
    unsigned char gh[24] = {0};
    if (fread(gh, 1, 24, f) != 24) {
        fclose(f);
        MessageBoxW(hwnd, L"文件头无效", L"错误", MB_ICONERROR);
        return;
    }
    bool littleMagic = (gh[0] == 0xd4 && gh[1] == 0xc3 && gh[2] == 0xb2 && gh[3] == 0xa1);
    bool nanoMagic = (gh[0] == 0x4d && gh[1] == 0x3c && gh[2] == 0xb2 && gh[3] == 0xa1);
    if (!littleMagic && !nanoMagic) {
        fclose(f);
        MessageBoxW(hwnd, L"暂时仅支持经典 PCAP 格式", L"提示", MB_ICONWARNING);
        return;
    }
    auto toSystemTime = [](unsigned int sec) {
        ULARGE_INTEGER ft;
        ft.QuadPart = (ULONGLONG)sec * 10000000ULL + 116444736000000000ULL;
        FILETIME fileTime;
        fileTime.dwLowDateTime = ft.LowPart;
        fileTime.dwHighDateTime = ft.HighPart;
        SYSTEMTIME st = {0};
        FileTimeToSystemTime(&fileTime, &st);
        return st;
    };
    unsigned long long loaded = 0;
    while (!feof(f)) {
        unsigned char ph[16] = {0};
        size_t got = fread(ph, 1, 16, f);
        if (got == 0) break;
        if (got != 16) break;
        unsigned int sec = (unsigned int)(ph[0] | (ph[1] << 8) | (ph[2] << 16) | (ph[3] << 24));
        unsigned int usec = (unsigned int)(ph[4] | (ph[5] << 8) | (ph[6] << 16) | (ph[7] << 24));
        unsigned int incl = (unsigned int)(ph[8] | (ph[9] << 8) | (ph[10] << 16) | (ph[11] << 24));
        unsigned int orig = (unsigned int)(ph[12] | (ph[13] << 8) | (ph[14] << 16) | (ph[15] << 24));
        if (incl == 0 || incl > 16 * 1024 * 1024) break;
        std::vector<unsigned char> data(incl);
        if (fread(data.data(), 1, incl, f) != incl) break;
        PacketRecord* rec = new PacketRecord();
        rec->time = toSystemTime(sec);
        rec->ts_sec = sec;
        rec->ts_usec = usec;
        rec->len = orig ? orig : incl;
        rec->data = std::move(data);
        InsertPacket(rec);
        ++loaded;
    }
    fclose(f);
    std::wstring msg = L"已打开 " + std::to_wstring(loaded) + L" 个数据包";
    MessageBoxW(hwnd, msg.c_str(), L"打开成功", MB_OK | MB_ICONINFORMATION);
}

static void ExportStatsCsv(HWND hwnd) {
    wchar_t path[MAX_PATH] = {0};
    if (!PickSaveFile(hwnd, path, MAX_PATH, L"CSV 文件 (*.csv)\0*.csv\0所有文件 (*.*)\0*.*\0", L"csv")) return;
    FILE* f = _wfopen(path, L"wb");
    if (!f) {
        MessageBoxW(hwnd, L"无法创建文件", L"错误", MB_ICONERROR);
        return;
    }
    struct Row { std::wstring section; std::wstring item; unsigned long packets; unsigned long long bytes; };
    std::vector<Row> rows;
    EnterCriticalSection(&g.cs);
    for (auto& p : g.protoCount) rows.push_back({ L"协议", p.first, p.second, g.protoBytes[p.first] });
    for (auto& p : g.endpointCount) rows.push_back({ L"地址", p.first, p.second, g.endpointBytes[p.first] });
    LeaveCriticalSection(&g.cs);
    std::string csv = "\xEF\xBB\xBFsection,item,packets,bytes\r\n";
    for (auto& r : rows) {
        csv += ToA(r.section) + "," + ToA(r.item) + "," + std::to_string(r.packets) + "," + std::to_string(r.bytes) + "\r\n";
    }
    fwrite(csv.data(), 1, csv.size(), f);
    fclose(f);
    MessageBoxW(hwnd, L"统计已导出为 CSV 文件", L"导出成功", MB_OK | MB_ICONINFORMATION);
}

static void DrawRoundedCard(HDC hdc, RECT rect, COLORREF fill, COLORREF border, int radius = 18) {
    HBRUSH brush = CreateSolidBrush(fill);
    HBRUSH borderBrush = CreateSolidBrush(border);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
    HRGN region = CreateRoundRectRgn(rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    FillRgn(hdc, region, brush);
    FrameRgn(hdc, region, borderBrush, 1, 1);
    SelectObject(hdc, oldBrush);
    DeleteObject(region);
    DeleteObject(borderBrush);
    DeleteObject(brush);
}

static void DrawStyledButton(LPDRAWITEMSTRUCT item, const wchar_t* text, COLORREF fill, COLORREF textColor, bool disabled = false) {
    HDC hdc = item->hDC;
    RECT rect = item->rcItem;
    HBRUSH brush = CreateSolidBrush(disabled ? RGB(232, 232, 237) : fill);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
    HBRUSH borderBrush = CreateSolidBrush(disabled ? RGB(209, 209, 214) : fill);
    HRGN region = CreateRoundRectRgn(rect.left, rect.top, rect.right, rect.bottom, 16, 16);
    FillRgn(hdc, region, brush);
    FrameRgn(hdc, region, borderBrush, 1, 1);
    SelectObject(hdc, oldBrush);
    DeleteObject(region);
    DeleteObject(borderBrush);
    DeleteObject(brush);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, disabled ? RGB(174, 174, 178) : textColor);
    HFONT font = CreateFontW(-S(17), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    DrawTextW(hdc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_ERASEBKGND: {
        if (g.materialEnabled) return 1;
        RECT client;
        GetClientRect(hwnd, &client);
        HDC hdc = GetDC(hwnd);
        HBRUSH brush = CreateSolidBrush(APP_BG);
        FillRect(hdc, &client, brush);
        DeleteObject(brush);
        ReleaseDC(hwnd, hdc);
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT paint;
        HDC hdc = BeginPaint(hwnd, &paint);
        RECT client;
        GetClientRect(hwnd, &client);
        RECT topCard = {S(16), S(16), client.right - S(16), S(160)};
        RECT contentCard = {S(16), S(176), client.right - S(16), client.bottom - S(40)};
        DrawRoundedCard(hdc, topCard, CARD_BG, BORDER_RGB, S(18));
        DrawRoundedCard(hdc, contentCard, CARD_BG, BORDER_RGB, S(18));
        EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, CARD_BG);
        SetTextColor(hdc, TEXT_PRIMARY);
        static HBRUSH brush = CreateSolidBrush(CARD_BG);
        return (LRESULT)brush;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* item = (DRAWITEMSTRUCT*)lParam;
        if (item->CtlID == 1001) DrawStyledButton(item, L"开始捕获", ACCENT, RGB(255, 255, 255), !IsWindowEnabled(item->hwndItem));
        else if (item->CtlID == 1002) DrawStyledButton(item, L"停止捕获", RGB(255, 235, 238), DANGER, !IsWindowEnabled(item->hwndItem));
        else if (item->CtlID == 1003) DrawStyledButton(item, L"清空", RGB(242, 242, 247), TEXT_PRIMARY, false);
        else if (item->CtlID == 1004) DrawStyledButton(item, L"应用过滤", RGB(233, 243, 255), ACCENT, false);
        else if (item->CtlID == 1005) DrawStyledButton(item, L"统计", RGB(233, 243, 255), ACCENT, false);
        else if (item->CtlID == 1101) DrawStyledButton(item, L"TCP", RGB(232, 243, 255), ACCENT, false);
        else if (item->CtlID == 1102) DrawStyledButton(item, L"UDP", RGB(235, 247, 235), SUCCESS, false);
        else if (item->CtlID == 1103) DrawStyledButton(item, L"HTTP", RGB(255, 240, 246), RGB(255, 45, 85), false);
        else if (item->CtlID == 1104) DrawStyledButton(item, L"ARP", RGB(255, 249, 235), WARNING, false);
        else if (item->CtlID == 1105) DrawStyledButton(item, L"DNS", RGB(243, 240, 255), PURPLE, false);
        else if (item->CtlID == 1106) DrawStyledButton(item, L"TLS", RGB(235, 247, 247), TEAL, false);
        else if (item->CtlID == 1010) DrawStyledButton(item, L"保存PCAP", RGB(242, 242, 247), TEXT_PRIMARY, false);
        else if (item->CtlID == 1011) DrawStyledButton(item, L"打开PCAP", RGB(242, 242, 247), TEXT_PRIMARY, false);
        else if (item->CtlID == 1013) DrawStyledButton(item, L"导出统计", RGB(233, 243, 255), ACCENT, false);
        else if (item->CtlID == 1012) {
            bool checked = (SendMessageW(item->hwndItem, BM_GETCHECK, 0, 0) == BST_CHECKED);
            DrawStyledButton(item, checked ? L"混杂模式 开" : L"混杂模式 关", checked ? ACCENT : RGB(242, 242, 247), checked ? RGB(255, 255, 255) : TEXT_PRIMARY, false);
        }
        return TRUE;
    }
    case WM_CREATE: {
        g.mainWnd = hwnd;
        break;
    }
    case WM_PACKET: {
        PacketRecord* rec = (PacketRecord*)lParam;
        InsertPacket(rec);
        return 0;
    }
    case WM_STATUS: {
        std::wstring* s = (std::wstring*)lParam;
        if (s) {
            g.statusText = *s;
            SendMessageW(g.statusBar, SB_SETTEXTW, 0, (LPARAM)g.statusText.c_str());
        }
        delete s;
        return 0;
    }
    case WM_CAPTURE_STOPPED: {
        g.running = false;
        ResetCaptureButtons(hwnd);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == 1001) { // start
            StartCapture(hwnd);
        } else if (id == 1002) { // stop
            StopCapture(hwnd);
        } else if (id == 1003) { // clear
            StopCapture(hwnd);
            ClearPackets();
            if (g.packetList) ListView_SetItemState(g.packetList, -1, 0, LVIS_SELECTED);
        } else if (id == 1004) { // apply filter
            ApplyFilterNow(hwnd);
        } else if (id == 1005) { // stats
            ShowStatsWindow(hwnd);
        } else if (id == 1006) { // about
            std::wstring msg = L"网络嗅探器 by LianHaoruiSec mhszed\n";
            if (p_pcap_lib_version) msg += ToW(p_pcap_lib_version());
            MessageBoxW(hwnd, msg.c_str(), L"关于", MB_OK);
        } else if (id == 1101) {
            SetFilterText(hwnd, L"tcp");
        } else if (id == 1102) {
            SetFilterText(hwnd, L"udp");
        } else if (id == 1103) {
            SetFilterText(hwnd, L"tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8888");
        } else if (id == 1104) {
            SetFilterText(hwnd, L"arp");
        } else if (id == 1105) {
            SetFilterText(hwnd, L"udp port 53 or tcp port 53");
        } else if (id == 1106) {
            SetFilterText(hwnd, L"tcp port 443 or tcp port 8443");
        } else if (id == 1010) {
            StopCapture(hwnd);
            SavePacketsPcap(hwnd);
        } else if (id == 1011) {
            StopCapture(hwnd);
            ClearPackets();
            LoadPacketsPcap(hwnd);
        } else if (id == 1012) {
            g.promiscuous = (SendMessageW(GetDlgItem(hwnd, 1012), BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (g.running) ApplyFilterNow(hwnd);
        } else if (id == 1013) {
            ExportStatsCsv(hwnd);
        }
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lParam;
        if (nh->idFrom == 2001 && nh->code == LVN_ITEMCHANGED) {
            NMLISTVIEW* lv = (NMLISTVIEW*)lParam;
            if (lv->uNewState & LVIS_SELECTED) ShowDetails(lv->iItem);
        } else if (nh->idFrom == 2001 && nh->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* draw = (NMLVCUSTOMDRAW*)lParam;
            if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                draw->clrTextBk = RGB(255,255,255);
                draw->clrText = RGB(28,28,30);
                PacketRecord* rec = (PacketRecord*)draw->nmcd.lItemlParam;
                if (rec) {
                    std::wstring proto = ToW(rec->proto);
                    if (proto == L"TCP") draw->clrTextBk = RGB(232,243,255);
                    else if (proto == L"UDP") draw->clrTextBk = RGB(235,247,235);
                    else if (proto == L"ARP") draw->clrTextBk = RGB(255,249,235);
                    else if (proto == L"ICMP") draw->clrTextBk = RGB(255,244,245);
                    else if (proto == L"IGMP") draw->clrTextBk = RGB(243,240,255);
                    else if (proto == L"HTTP") draw->clrTextBk = RGB(255,240,246);
                }
                return CDRF_DODEFAULT;
            }
        }
        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        int statusH = S(30);
        int margin = S(24);
        int top = S(176);
        int availableH = h - statusH - top - margin * 2;
        int listH = availableH * 55 / 100;
        int detailH = availableH * 30 / 100;
        int hexH = availableH - listH - detailH;
        MoveWindow(g.statusBar, 0, h - statusH, w, statusH, TRUE);
        MoveWindow(g.packetList, margin, top, w - margin * 2, listH, TRUE);
        MoveWindow(g.detailTree, margin, top + listH + S(12), w - margin * 2, detailH, TRUE);
        MoveWindow(g.hexEdit, margin, top + listH + detailH + S(24), w - margin * 2, hexH, TRUE);
        RECT listRect;
        GetClientRect(g.packetList, &listRect);
        int listW = listRect.right - listRect.left;
        if (listW > S(600)) {
            int noW = S(56);
            int timeW = S(96);
            int protoW = S(70);
            int lenW = S(64);
            int addrW = (listW - noW - timeW - protoW - lenW - S(22)) * 22 / 100;
            int infoW = listW - noW - timeW - addrW - addrW - protoW - lenW - S(2);
            ListView_SetColumnWidth(g.packetList, 0, noW);
            ListView_SetColumnWidth(g.packetList, 1, timeW);
            ListView_SetColumnWidth(g.packetList, 2, addrW);
            ListView_SetColumnWidth(g.packetList, 3, addrW);
            ListView_SetColumnWidth(g.packetList, 4, protoW);
            ListView_SetColumnWidth(g.packetList, 5, lenW);
            ListView_SetColumnWidth(g.packetList, 6, infoW);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* info = (MINMAXINFO*)lParam;
        info->ptMinTrackSize.x = S(900);
        info->ptMinTrackSize.y = S(620);
        return 0;
    }
    case WM_DESTROY: {
        StopCapture(hwnd);
        DeleteCriticalSection(&g.cs);
        PostQuitMessage(0);
        break;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void CreateControls(HWND hwnd) {
    HFONT font = CreateFontW(-S(17), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    HFONT bold = CreateFontW(-S(19), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    CreateWindowW(L"STATIC", L"网卡", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, S(28), S(22), S(48), S(30), hwnd, NULL, g.hInst, NULL);
    g.adapterCombo = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, S(78), S(20), S(260), S(300), hwnd, (HMENU)9001, g.hInst, NULL);
    CreateWindowW(L"STATIC", L"过滤", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, S(352), S(22), S(48), S(30), hwnd, NULL, g.hInst, NULL);
    g.filterEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, S(404), S(20), S(340), S(32), hwnd, (HMENU)9002, g.hInst, NULL);

    g.startBtn = CreateWindowW(L"BUTTON", L"开始捕获", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(28), S(62), S(108), S(34), hwnd, (HMENU)1001, g.hInst, NULL);
    g.stopBtn = CreateWindowW(L"BUTTON", L"停止捕获", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_DISABLED, S(142), S(62), S(108), S(34), hwnd, (HMENU)1002, g.hInst, NULL);
    g.clearBtn = CreateWindowW(L"BUTTON", L"清空", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(256), S(62), S(76), S(34), hwnd, (HMENU)1003, g.hInst, NULL);
    g.applyBtn = CreateWindowW(L"BUTTON", L"应用过滤", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(340), S(62), S(96), S(34), hwnd, (HMENU)1004, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"统计", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(444), S(62), S(76), S(34), hwnd, (HMENU)1005, g.hInst, NULL);

    CreateWindowW(L"BUTTON", L"TCP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(28), S(102), S(52), S(32), hwnd, (HMENU)1101, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"UDP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(84), S(102), S(52), S(32), hwnd, (HMENU)1102, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"HTTP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(141), S(102), S(60), S(32), hwnd, (HMENU)1103, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"ARP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(206), S(102), S(52), S(32), hwnd, (HMENU)1104, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"DNS", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(263), S(102), S(52), S(32), hwnd, (HMENU)1105, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"TLS", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(320), S(102), S(52), S(32), hwnd, (HMENU)1106, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"保存PCAP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(388), S(102), S(92), S(32), hwnd, (HMENU)1010, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"打开PCAP", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(486), S(102), S(92), S(32), hwnd, (HMENU)1011, g.hInst, NULL);
    CreateWindowW(L"BUTTON", L"导出统计", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(586), S(102), S(92), S(32), hwnd, (HMENU)1013, g.hInst, NULL);
    g.promiscBtn = CreateWindowW(L"BUTTON", L"混杂模式", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_AUTOCHECKBOX, S(692), S(102), S(100), S(32), hwnd, (HMENU)1012, g.hInst, NULL);
    SendMessageW(g.promiscBtn, BM_SETCHECK, BST_CHECKED, 0);

    g.packetList = CreateWindowExW(0, WC_LISTVIEWW, NULL, WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | WS_BORDER, S(16), S(74), S(1000), S(300), hwnd, (HMENU)2001, g.hInst, NULL);
    SetWindowTheme(g.packetList, L"Explorer", NULL);
    ListView_SetExtendedListViewStyle(g.packetList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    const wchar_t* cols[] = { L"序号", L"时间", L"源地址", L"目的地址", L"协议", L"长度", L"信息" };
    int baseWidths[] = { 60, 100, 150, 150, 70, 70, 500 };
    for (int i = 0; i < 7; ++i) {
        col.pszText = (LPWSTR)cols[i];
        col.cx = S(baseWidths[i]);
        ListView_InsertColumn(g.packetList, i, &col);
    }
    g.detailTree = CreateWindowExW(0, WC_TREEVIEWW, NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS, S(16), S(384), S(1000), S(200), hwnd, (HMENU)2002, g.hInst, NULL);
    SetWindowTheme(g.detailTree, L"Explorer", NULL);
    g.hexEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, S(16), S(590), S(1000), S(150), hwnd, (HMENU)2003, g.hInst, NULL);
    g.statusBar = CreateWindowExW(0, STATUSCLASSNAMEW, NULL, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, S(1000), S(30), hwnd, (HMENU)3001, g.hInst, NULL);
    int statusParts[] = { -1 };
    SendMessageW(g.statusBar, SB_SETPARTS, 1, (LPARAM)statusParts);
    SendMessageW(g.adapterCombo, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.filterEdit, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.packetList, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.detailTree, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.hexEdit, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.statusBar, WM_SETFONT, (WPARAM)font, TRUE);
    SendMessageW(g.startBtn, WM_SETFONT, (WPARAM)bold, TRUE);
    SendMessageW(g.stopBtn, WM_SETFONT, (WPARAM)bold, TRUE);
    SendMessageW(g.clearBtn, WM_SETFONT, (WPARAM)bold, TRUE);
    SendMessageW(g.applyBtn, WM_SETFONT, (WPARAM)bold, TRUE);
    SendMessageW(g.promiscBtn, WM_SETFONT, (WPARAM)bold, TRUE);
}

static void EnablePerMonitorDpiAwareness() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef BOOL (WINAPI *SetDpiAwarenessContextFn)(HANDLE);
        SetDpiAwarenessContextFn setContext = (SetDpiAwarenessContextFn)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (setContext) {
            setContext((HANDLE)-4);
            return;
        }
    }
    typedef BOOL (WINAPI *SetProcessDpiAwareFn)();
    SetProcessDpiAwareFn setAware = (SetProcessDpiAwareFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDPIAware");
    if (setAware) setAware();
}

static void UpdateDpiForWindow(HWND hwnd) {
    typedef UINT (WINAPI *GetDpiForWindowFn)(HWND);
    GetDpiForWindowFn getDpi = (GetDpiForWindowFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow");
    if (getDpi) {
        UINT dpi = getDpi(hwnd);
        if (dpi > 0) g_dpi = (int)dpi;
    }
}

static void EnableWindowBackdrop(HWND hwnd) {
    HMODULE dwm = GetModuleHandleW(L"dwmapi.dll");
    if (!dwm) dwm = LoadLibraryW(L"dwmapi.dll");
    if (dwm) {
        typedef HRESULT (WINAPI *DwmSetWindowAttributeFn)(HWND, DWORD, LPCVOID, DWORD);
        DwmSetWindowAttributeFn dwmSet = (DwmSetWindowAttributeFn)GetProcAddress(dwm, "DwmSetWindowAttribute");
        if (dwmSet) {
            DWORD corner = 2;
            dwmSet(hwnd, 33, &corner, sizeof(corner));
            DWORD backdrop = 2;
            if (SUCCEEDED(dwmSet(hwnd, 38, &backdrop, sizeof(backdrop)))) {
                g.materialEnabled = true;
            }
            if (g.materialEnabled) {
                BOOL mica = TRUE;
                if (!SUCCEEDED(dwmSet(hwnd, 1029, &mica, sizeof(mica)))) {
                    DWORD transparent = 2;
                    dwmSet(hwnd, 38, &transparent, sizeof(transparent));
                }
            }
        }
    }
    if (!g.materialEnabled) {
        struct AccentPolicy {
            int AccentState;
            int AccentFlags;
            DWORD GradientColor;
            int AnimationId;
        };
        struct WindowCompositionAttributeData {
            int Attrib;
            void* pvData;
            SIZE_T cbData;
        };
        typedef BOOL (WINAPI *SetWindowCompositionAttributeFn)(HWND, WindowCompositionAttributeData*);
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        SetWindowCompositionAttributeFn setComp = (SetWindowCompositionAttributeFn)GetProcAddress(user32, "SetWindowCompositionAttribute");
        if (setComp) {
            AccentPolicy policy = {0};
            policy.AccentState = 4;
            policy.AccentFlags = 2;
            policy.GradientColor = 0xB3FFFFFF;
            WindowCompositionAttributeData data = {19, &policy, sizeof(policy)};
            if (setComp(hwnd, &data)) g.materialEnabled = true;
        }
    }
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    EnablePerMonitorDpiAwareness();
    InitializeCriticalSection(&g.cs);
    g.hInst = hInst;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"CppModernWinPcapSnifferWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                 GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    wc.hbrBackground = NULL;
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(0, L"CppModernWinPcapSnifferWnd", L"网络嗅探器 by LianHaoruiSec mhszed", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, S(1280), S(850), NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)wc.hIcon);
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)wc.hIconSm);
    UpdateDpiForWindow(hwnd);
    EnableWindowBackdrop(hwnd);
    CreateControls(hwnd);
    g.statusText = L"就绪";
    SendMessageW(g.statusBar, SB_SETTEXTW, 0, (LPARAM)g.statusText.c_str());
    if (!LoadWinPcapAPI()) {
        MessageBoxW(hwnd, L"未找到 WinPcap/Npcap 运行库", L"错误", MB_ICONERROR);
    } else {
        char errbuf[256] = {0};
        pcap_if_t* alldevs = NULL;
        if (p_pcap_findalldevs(&alldevs, errbuf) != -1) {
            for (pcap_if_t* d = alldevs; d; d = d->next) {
                AdapterInfo info;
                info.name = ToW(d->name ? d->name : "");
                info.desc = ToW(d->description ? d->description : "");
                std::wstring text = info.desc.empty() ? info.name : info.desc;
                SendMessageW(g.adapterCombo, CB_ADDSTRING, 0, (LPARAM)text.c_str());
                g.adapters.push_back(info);
            }
            p_pcap_freealldevs(alldevs);
        }
        if (!g.adapters.empty()) {
            int prefer = 0;
            int wifiFallback = -1;
            for (int idx = 0; idx < (int)g.adapters.size(); ++idx) {
                std::wstring text = g.adapters[idx].desc.empty() ? g.adapters[idx].name : g.adapters[idx].desc;
                if (text.find(L"MediaTek") != std::wstring::npos && text.find(L"Wi-Fi") != std::wstring::npos) {
                    prefer = idx;
                    break;
                }
                if (wifiFallback < 0 && text.find(L"Wi-Fi") != std::wstring::npos) wifiFallback = idx;
            }
            if (prefer == 0 && wifiFallback >= 0) prefer = wifiFallback;
            SendMessageW(g.adapterCombo, CB_SETCURSEL, (WPARAM)prefer, 0);
        }
    }
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

