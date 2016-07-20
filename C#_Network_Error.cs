using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Windows;

using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using System.Threading;

namespace Network2_
{

    class Program
    {
        static void Main(string[] args)
        {
            string path = Directory.GetCurrentDirectory() + "/network.txt";
            FileStream fs = new FileStream(path, FileMode.Create);
            StreamWriter sw = new StreamWriter(fs);
            



            // 네트워크 장치 검색
            var networkInterface = SharpPcap.CaptureDeviceList.Instance;
            if (networkInterface.Count < 1)
            {
                Console.WriteLine("No network interface.");
                return;
            }

           // Console.WriteLine(networkInterface[3]);
    
            sw.Write(networkInterface[3]);
            sw.Close();
            sw.Dispose();

            FileStream fs2 = new FileStream(path, FileMode.Open);
            StreamReader sr = new StreamReader(fs2);

            String Gateway = sr.ReadToEnd();
            Console.WriteLine(Gateway);
            sr.Close();
            sr.Dispose();


            // Millisecond 단위 이며 초기연결 지연설정
            int readTimeout = 1000;

            // 현재 단말기의 네트워크 장치의 리스트들을 불러온다.
            CaptureDeviceList devices = CaptureDeviceList.Instance;

            // 무선 랜카드의 인덱스 번호는 1번(단말기 설정에 따라 다름)
            ICaptureDevice device = devices[3];

            // 무선 랜카드를 프러미스큐어스 모드로 연다.
            device.Open(DeviceMode.Promiscuous, readTimeout);

            IPAddress dstIP = null;
            IPAddress srcIP = null;
            PhysicalAddress dstMac = null;
            PhysicalAddress srcMac = null;

            dstIP = IPAddress.Parse("100.0.0.100");
            dstMac = PhysicalAddress.Parse("AA-AA-AA-AA-AA-AA");
            srcIP = IPAddress.Parse("111.0.0.111");
            srcMac = PhysicalAddress.Parse("BB-BB-BB-BB-BB-BB");

            Console.WriteLine(IPAddress.Broadcast);
            Console.WriteLine(dstMac);
            Console.WriteLine(srcIP);
            Console.WriteLine(srcMac);


            ARPPacket arp = new ARPPacket(ARPOperation.Response, dstMac, dstIP, srcMac, srcIP);
            EthernetPacket eth = new EthernetPacket(srcMac, dstMac, EthernetPacketType.Arp);
            arp.PayloadData = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            eth.PayloadPacket = arp;
            device.SendPacket(eth);




            // 네트워크 장치 정보 출력
            /*
            foreach (var interfaceInfo in networkInterface)
            {
                
                Console.WriteLine("{0}", interfaceInfo);
                Console.WriteLine("========================================");
            }*/

        }
    }
}
