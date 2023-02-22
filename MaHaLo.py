# -*- coding: utf-8 -*-
"""
MaHaLo - Passive Recon Enumeration with public services. 
"""

__author__      = "Jose Moruno Cadima"
__copyright__   = "Copyright 2023 www.sniferl4bs.com"
__license__ = "CC BY-NC-SA 4.0"
__version__ = "0.1"
__email__ = "sniferl4bs@gmail.com"



from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IRequestInfo

from java.awt import Component
from java.awt import BorderLayout
from java.io import PrintWriter
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JScrollPane
from javax.swing import JLabel
from javax.swing.table import AbstractTableModel
from threading import Thread


import re
import urllib2
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._jpanel = JTabbedPane()

        # Main tab

        self.main_tab = JPanel()
        self.main_tab.setLayout(BorderLayout())
        self._jpanel.addTab("Subdomains Enumeration", self.main_tab)

        # Add domain name text field
        self.domain_name_field = JTextField("Enter domain name")
        self.main_tab.add(self.domain_name_field, BorderLayout.NORTH)

        # Add search button to main tab
        self.search_button = JButton("Search", actionPerformed=self.search_subdomains)
        self.main_tab.add(self.search_button, BorderLayout.SOUTH)

        # Whois TAB
        tab_whois = JPanel()
        tab_whois.setLayout(BorderLayout())
        tab_whois_text_area = JTextArea("whois")
        tab_whois_text_area.setEditable(False)
        scroll_pane = JScrollPane(tab_whois_text_area)
        tab_whois.add(scroll_pane, BorderLayout.CENTER)
        self._jpanel.addTab("Whois", tab_whois) 

        # Api TAB
        tab_apikey = JPanel()
        tab_apikey.setLayout(BorderLayout())
        tab_apikey_text_area = JTextArea("API KEY")
        tab_apikey_text_area.setEditable(False)
        scroll_pane = JScrollPane(tab_apikey_text_area)
        tab_apikey.add(scroll_pane, BorderLayout.CENTER)
        self._jpanel.addTab("API KEY", tab_apikey) 


        # About TAB
        tab_about = JPanel()
        tab_about.setLayout(BorderLayout())
        tab_about_text_area = JTextArea("Este es un plug-in creado con el fin de aprender sobre la api de Burp Suite. Por lo que es un Plugin en fase de desarrollo y cambios constantes.\n\n Actualmente el plug-in permite realizar la enumeracion de Subdominios de manera pasiva utlizando los siguientes servicios:\n\n  - crt.sh \n - SecurityTrails (Necesitas una api Key) \n - Hacker Target \n\n- Shodan \n\n Quieres conocer mas sobre el plugin visita www.sniferl4bs.com o el Canal de YouTube www.youtube.com/SniferL4bs \n\n Atte: Jose Moruno Cadima aka Snifer. ")
        tab_about_text_area.setEditable(False)
        scroll_pane = JScrollPane(tab_about_text_area)
        tab_about.add(scroll_pane, BorderLayout.CENTER)
        self._jpanel.addTab("About", tab_about)    


        # Add results table to main tab
        self.table = JTable()
        self.main_tab.add(JScrollPane(self.table), BorderLayout.CENTER)
        callbacks.addSuiteTab(self)

        # Function search Subdomains
    def search_subdomains(self, event):
        domain_name = self.domain_name_field.getText()
        
        #Search subdomains using crt.sh. 
        url = "https://crt.sh/?q=%25." + domain_name + "&output=json"
        response = urllib2.urlopen(url)
        data = json.loads(response.read())
        subdomains = set()
        for domain in data:
            name_value = domain['name_value']
            if not re.match(r"^[\w\.\-]+\.[a-zA-Z]{2,}$", name_value):  
                continue
            if name_value in subdomains:
                continue
            subdomains.add(name_value)

        # Search subdomains using SecurityTrails
        url = "https://api.securitytrails.com/v1/domain/" + domain_name + "/subdomains"
        headers = {"apikey": "API_KEY_HERE"} #TODO: add APIKEY in API KEY TAB. 
        req = urllib2.Request(url, headers=headers)
        response = urllib2.urlopen(req)
        data = json.loads(response.read())

        security_trails_subdomains = set()
        for subdomain in data.get("subdomains", []):
            security_trails_subdomains.add(subdomain + "." + domain_name)
        
        # Search subdomains using HackerTarget API  
        url = "https://api.hackertarget.com/hostsearch/?q=" + domain_name
        response_hackertarget = urllib2.urlopen(url)
        if response_hackertarget.getcode() == 200:
            domain_list = response.read().split('\n')
            for line in domain_list:
                subdomain = line.split(',')
                if len(subdomain) > 0:
                    hackertarget_subdomains = subdomain[0]

        # Combine subdomains found
        subdomains = subdomains.union(security_trails_subdomains, hackertarget_subdomains)

        # Threads check website
        result_dict = {}
        threads = []
        for subdomain in subdomains:
            thread = DomainChecker(subdomain, result_dict)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        rows = [[k, v] for k, v in result_dict.items()]
        self.table.setModel(self.TableModel(rows, ["Subdomains", "Alive?"]))    

    def getTabCaption(self):
        return "MaHaLo"

    def getUiComponent(self):
        return self._jpanel

    class TableModel(AbstractTableModel):
        def __init__(self, rows, columns):
            self.rows = rows
            self.columns = columns

        def getRowCount(self):
            return len(self.rows)

        def getColumnCount(self):
            return len(self.columns)

        def getColumnName(self, columnIndex):
            return self.columns[columnIndex]

        def getValueAt(self, rowIndex, columnIndex):
            return self.rows[rowIndex][columnIndex]


class DomainChecker(Thread):
    def __init__(self, domain, result_dict):
        super(DomainChecker, self).__init__()
        self.domain = domain
        self.result_dict = result_dict

    def run(self):
        try:
            # Check if the domain is reachable on HTTP port 80
            urllib2.urlopen('http://' + self.domain, timeout=2)
            self.result_dict[self.domain] = 'Alive (HTTP)'
        except:
            pass

        try:
            # Check if the domain is reachable on HTTPS port 443
            urllib2.urlopen('https://' + self.domain, timeout=2)
            self.result_dict[self.domain] = 'Alive (HTTPS)'
        except:
            pass

        # If neither HTTP nor HTTPS works, the domain is assumed to be dead
        if self.domain not in self.result_dict:
            self.result_dict[self.domain] = 'Dead '



