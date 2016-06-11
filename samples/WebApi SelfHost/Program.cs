using System;
using System.Net.Http;
using Microsoft.Owin.Hosting;

namespace WebApi_SelfHost
{
    public class Program
    {
        static void Main()
        {
            const string url = @"http://localhost:32431";
            using (WebApp.Start<Startup>(url))
            {
                Console.WriteLine(url);
                try
                {
                    var client = new HttpClient();

                    var response = client.GetAsync(url + "/api/Example/Authorized").Result;

                    Console.WriteLine(response);
                    Console.WriteLine(response.Content.ReadAsStringAsync().Result);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                Console.ReadLine();
            }
        }
    }
}