/*
 * Port scanner. Project 2 for IPK.
 * Author: Daniel Pohancanik <xpohan03@stud.fit.vutbr.cz>
*/

using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ipk2scan
{
    class Program
    {
        static void Main(string[] args)
        {
            string uPorts = "";
            string tPorts = "";
            string intr = "";
            string target = "";

            /////ARGUMENT PROCESSING START/////
            if (args.Length < 2)
            {
                Console.WriteLine("Insufficient params");
            }
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-i")
                {
                    if (args[i + 1] == "-t" || args[i + 1] == "--pt" || args[i + 1] == "iu" || args[i + 1] == "--pu")
                    {
                        Console.WriteLine("Interface expected\n");
                        Environment.Exit(1);
                    }
                    intr = args[i + 1];
                    i++;
                }
                else if (args[i] == "-t" || args[i] == "--pt")
                {
                    Regex reg = new Regex(@"(^(\d*\,)*\d*$|^\d*\-\d*$)");
                    MatchCollection matches = reg.Matches(args[i + 1]);
                    if (matches.Count != 1)
                    {
                        Console.WriteLine("Incorrect arg format\n");
                        Environment.Exit(1);
                    }
                    else
                    {
                        tPorts = args[i + 1];
                        i++;
                    }
                }
                else if (args[i] == "-u" || args[i] == "--pu")
                {
                    Regex reg1 = new Regex(@"(^(\d*\,)*\d*$|^\d*\-\d*$)");
                    MatchCollection matches1 = reg1.Matches(args[i + 1]);
                    if (matches1.Count != 1)
                    {
                        Console.WriteLine("Incorrect arg format\n");
                        Environment.Exit(1);
                    }
                    else
                    {
                        uPorts = args[i + 1];
                        i++;
                    }
                }
                else if (i == (args.Length) - 1 && (tPorts != "" || uPorts != ""))
                {
                    target = args[i];
                }
                else
                {
                    Console.WriteLine("Unrecognized arguemnt\n");
                    Environment.Exit(1);
                }

            }
            if (target == "")
            {
                Console.WriteLine("Missing address argument \n");
                Environment.Exit(1);
            }

            Console.WriteLine(intr + " " + tPorts + " " + uPorts + " " + "target= " + target);


            //CREATING OF PORT ARRAY FOR TCP
            string[] tPortsSplit = tPorts.Split('-');
            ArrayList tPortsArr = new ArrayList();
            if (tPortsSplit.Length > 1)
            {
                for (int i = Int32.Parse(tPortsSplit[0]); i <= Int32.Parse(tPortsSplit[1]); i++)
                {

                    tPortsArr.Add(i.ToString());
                }
            }
            tPortsSplit = tPorts.Split(',');
            if (tPortsSplit.Length > 1)
            {
                foreach (string port in tPortsSplit)
                {
                    if(port == "")
                    {
                        continue;
                    }
                    tPortsArr.Add(port);
                }
            }
            if (tPortsArr.Count == 0 && tPorts != "")
            {
                tPortsArr.Add(tPorts);
            }
           

            //CREATING OF PORT ARRAY FOR UDP
            string[] uPortsSplit = uPorts.Split('-');
            ArrayList uPortsArr = new ArrayList();
            if (uPortsSplit.Length > 1)
            {
                for (int i = Int32.Parse(uPortsSplit[0]); i <= Int32.Parse(uPortsSplit[1]); i++)
                {


                    uPortsArr.Add(i.ToString());
                }
            }
            
            uPortsSplit = uPorts.Split(',');
            if (uPortsSplit.Length > 1)
            {
                foreach (string port in uPortsSplit)
                {
                    if (port == "")
                    {
                        continue;
                    }
                    else
                    {
                        uPortsArr.Add(port);
                    }   
                }
            }
            if (uPortsArr.Count == 0 && uPorts != "")
            {
                uPortsArr.Add(uPorts);
            }
            /////ARGUMENT PROCESSING END/////
      
            Console.WriteLine("Target name: " + target);
            Console.WriteLine("Interface : {0}", intr);
            ArrayList tcpResults = new ArrayList();
            ArrayList udpResults = new ArrayList();

            ////IP address lookup. Localhost is explicitely set to 127.0.0.1.
            if(target != "localhost")
            {
                try
                {
                    IPAddress[] addresses = Dns.GetHostAddresses(target);
                    target = addresses[0].ToString();
                }
                catch
                {
                    Console.WriteLine("Address not found");
                    Environment.Exit(1);
                }
                
            }
            else
            {
                target = "127.0.0.1";
            }
            ////IP Address lookup end


            Console.WriteLine("Target address: " + target);

            //Creation of threads which will perform tcp scans and print results as they come.
            if (tPortsArr.Count != 0)
            {
                foreach (string port in tPortsArr)
                {
                    Thread newThread = new Thread(delegate ()
                    {

                        var ret = CheckTcp(port, target);
                        if (ret == 0)
                        {

                            Console.WriteLine("Port " + port + "/tcp is open");
                        }
                        else if (ret == 1)
                        {
                            Console.WriteLine("Port " + port + "/tcp is closed");
                        }
                        else
                        {
                            Console.WriteLine("Port " + port + "/tcp is filtered");
                        }

                    });
                    newThread.Start();
                }

            }
            //Creation of threads which will perform udp scans and print results as they come.
            if (uPortsArr.Count != 0)
            {
                foreach (string port in uPortsArr)
                {
                    Thread newThread2 = new Thread(delegate ()
                    {

                        var ret = CheckUdp(target, port);
                        if (ret == 0)
                        {

                            Console.WriteLine("Port " + port + "/udp is open");

                        }
                        else
                        {
                            Console.WriteLine("Port " + port + "/udp is closed");
                        }
                    });
                    newThread2.Start();
                }
            }
        }

        //TCP Scanner
        private static int CheckTcp(string port, string target)
        {
            try
            {
                //Creatin of new client
                TcpClient tcp;
                if (target.Contains(":"))
                {
                    tcp = new TcpClient(AddressFamily.InterNetworkV6);
                }
                else
                {
                    tcp = new TcpClient();
                }
                //Trying to connect and waiting for confirmation for 4000 ms.
                if (!tcp.ConnectAsync(IPAddress.Parse(target), Int32.Parse(port)).Wait(4000))
                {
                    try
                    {
                        //Another try to determine whether its filtered or not.
                        TcpClient tcp2 = new TcpClient();
                        if (!tcp2.ConnectAsync(IPAddress.Parse(target), Int32.Parse(port)).Wait(4000))
                        {
                            //No response for second time. Its most likely filtered.
                            tcp.Close();
                            return 2;
                        }
                        else
                        {
                            //Response after second attempt. Port is open
                            tcp.Close();
                            return 0;
                        }
                    }
                    catch
                    {
                        //If the connection is refused, exception is thrown. Port is closed
                        tcp.Close();
                        return 1;
                    }
                }
                else
                {
                    //Response after first round of waiting
                    tcp.Close();
                    return 0;
                }
            }
            catch
            {
                
                return 1;
            }
        }

        //UDP Scan
        private static int CheckUdp(string addr, string port)
        {
            UdpClient udp;
            //Oversimplified check whether address is of version 4 or 6
            if(addr.Contains(":"))
            {
                udp = new UdpClient(AddressFamily.InterNetworkV6);
            }
            else
            {
                udp = new UdpClient();
            }

            IPEndPoint remEp = new IPEndPoint(IPAddress.Parse(addr), Int32.Parse(port));
            try
            {
                //Sending data to specified port.
                udp.Connect(remEp);
                Byte[] buffer = Encoding.ASCII.GetBytes("Identify yourself");
                udp.Send(buffer, buffer.Length);
                //Waiting up to 3000 ms. If the connection is forcibly refused, mark as closed. If nothing comes back mark is open.
                var res = udp.ReceiveAsync().Wait(3000);
                if (!res)
                {
                    udp.Close();
                    return 0;
                }
                else
                {
                    udp.Close();
                    return 1;
                }
            }
            catch
            {
                udp.Close();
                return 1;
            }
        }
    }
}

