<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * {
        font-family: Arial, Helvetica, sans-serif;
      }
      h1 {
        text-align: center;
      }
      .group-header th {
        font-size: 200%;
      }
      .sub-header th {
        font-size: 150%;
      }
      table, th, td {
        border: 1px solid black;
        border-collapse: collapse;
        white-space: nowrap;
        padding: .3em;
      }
      table {
        margin: 0 auto;
      }
      .severity {
        text-align: center;
        font-weight: bold;
        color: #fafafa;
      }
      .severity-LOW .severity { background-color: #5fbb31; }
      .severity-MEDIUM .severity { background-color: #e9c600; }
      .severity-HIGH .severity { background-color: #ff8800; }
      .severity-CRITICAL .severity { background-color: #e40000; }
      .severity-UNKNOWN .severity { background-color: #747474; }
      .severity-LOW { background-color: #5fbb3160; }
      .severity-MEDIUM { background-color: #e9c60060; }
      .severity-HIGH { background-color: #ff880060; }
      .severity-CRITICAL { background-color: #e4000060; }
      .severity-UNKNOWN { background-color: #74747460; }
      table tr td:first-of-type {
        font-weight: bold;
      }
      .links a,
      .links[data-more-links=on] a {
        display: block;
      }
      .links[data-more-links=off] a:nth-of-type(1n+5) {
        display: none;
      }
      a.toggle-more-links { cursor: pointer; }
    </style>
    <title>bitnami/minideb-extras (debian 9.11) - Trivy Report - 2022-01-31 16:01:53.547690091 +0000 UTC m=+1.313079016 </title>
    <script>
      window.onload = function() {
        document.querySelectorAll('td.links').forEach(function(linkCell) {
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {
            return a.href > b.href ? 1 : -1;
          });
          links.forEach(function(link, idx) {
            if (links.length > 3 && 3 === idx) {
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
          });
        });
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
          toggleLink.onclick = function() {
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          };
        });
      };
    </script>
  </head>
  <body>
    <h1>bitnami/minideb-extras (debian 9.11) - Trivy Report - 2022-01-31 16:01:53.547716991 +0000 UTC m=+1.313105816</h1>
    <table>
      <tr class="group-header"><th colspan="6">debian</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">apt</td>
        <td>CVE-2020-27350</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.9</td>
        <td>1.4.11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27350">https://access.redhat.com/security/cve/CVE-2020-27350</a>
          <a href="https://bugs.launchpad.net/bugs/1899193">https://bugs.launchpad.net/bugs/1899193</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350</a>
          <a href="https://security.netapp.com/advisory/ntap-20210108-0005/">https://security.netapp.com/advisory/ntap-20210108-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-4667-1">https://ubuntu.com/security/notices/USN-4667-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4667-2">https://ubuntu.com/security/notices/USN-4667-2</a>
          <a href="https://usn.ubuntu.com/usn/usn-4667-1">https://usn.ubuntu.com/usn/usn-4667-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4808">https://www.debian.org/security/2020/dsa-4808</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">apt</td>
        <td>CVE-2020-3810</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.9</td>
        <td>1.4.10</td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.launchpad.net/bugs/1878177">https://bugs.launchpad.net/bugs/1878177</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810</a>
          <a href="https://github.com/Debian/apt/issues/111">https://github.com/Debian/apt/issues/111</a>
          <a href="https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36">https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36</a>
          <a href="https://lists.debian.org/debian-security-announce/2020/msg00089.html">https://lists.debian.org/debian-security-announce/2020/msg00089.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/</a>
          <a href="https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6">https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6</a>
          <a href="https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6">https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6</a>
          <a href="https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/">https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/</a>
          <a href="https://ubuntu.com/security/notices/USN-4359-1">https://ubuntu.com/security/notices/USN-4359-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4359-2">https://ubuntu.com/security/notices/USN-4359-2</a>
          <a href="https://usn.ubuntu.com/4359-1/">https://usn.ubuntu.com/4359-1/</a>
          <a href="https://usn.ubuntu.com/4359-2/">https://usn.ubuntu.com/4359-2/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">bsdutils</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">curl</td>
        <td>CVE-2019-5481</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5481">https://access.redhat.com/security/cve/CVE-2019-5481</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5481.html">https://curl.haxx.se/docs/CVE-2019-5481.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5481">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5481</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5481.html">https://linux.oracle.com/cve/CVE-2019-5481.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1792.html">https://linux.oracle.com/errata/ELSA-2020-1792.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20191004-0003/">https://security.netapp.com/advisory/ntap-20191004-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-1">https://ubuntu.com/security/notices/USN-4129-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">curl</td>
        <td>CVE-2019-5482</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5482">https://access.redhat.com/security/cve/CVE-2019-5482</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5482.html">https://curl.haxx.se/docs/CVE-2019-5482.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5482">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5482</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5482.html">https://linux.oracle.com/cve/CVE-2019-5482.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5562.html">https://linux.oracle.com/errata/ELSA-2020-5562.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20191004-0003/">https://security.netapp.com/advisory/ntap-20191004-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200416-0003/">https://security.netapp.com/advisory/ntap-20200416-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-1">https://ubuntu.com/security/notices/USN-4129-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-2">https://ubuntu.com/security/notices/USN-4129-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2019-5436</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00008.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00008.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00017.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00017.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/09/11/6">http://www.openwall.com/lists/oss-security/2019/09/11/6</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5436">https://access.redhat.com/security/cve/CVE-2019-5436</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5436.html">https://curl.haxx.se/docs/CVE-2019-5436.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5436">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5436</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5436.html">https://linux.oracle.com/cve/CVE-2019-5436.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1792.html">https://linux.oracle.com/errata/ELSA-2020-1792.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SMG3V4VTX2SE3EW3HQTN3DDLQBTORQC2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SMG3V4VTX2SE3EW3HQTN3DDLQBTORQC2/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20190606-0004/">https://security.netapp.com/advisory/ntap-20190606-0004/</a>
          <a href="https://support.f5.com/csp/article/K55133295">https://support.f5.com/csp/article/K55133295</a>
          <a href="https://support.f5.com/csp/article/K55133295?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K55133295?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-3993-1">https://ubuntu.com/security/notices/USN-3993-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3993-2">https://ubuntu.com/security/notices/USN-3993-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2020-8177</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8177">https://access.redhat.com/security/cve/CVE-2020-8177</a>
          <a href="https://curl.haxx.se/docs/CVE-2020-8177.html">https://curl.haxx.se/docs/CVE-2020-8177.html</a>
          <a href="https://curl.se/docs/CVE-2020-8177.html">https://curl.se/docs/CVE-2020-8177.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8177">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8177</a>
          <a href="https://hackerone.com/reports/887462">https://hackerone.com/reports/887462</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8177.html">https://linux.oracle.com/cve/CVE-2020-8177.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5002.html">https://linux.oracle.com/errata/ELSA-2020-5002.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8177">https://nvd.nist.gov/vuln/detail/CVE-2020-8177</a>
          <a href="https://ubuntu.com/security/notices/USN-4402-1">https://ubuntu.com/security/notices/USN-4402-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2020-8231</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u12</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8231">https://access.redhat.com/security/cve/CVE-2020-8231</a>
          <a href="https://curl.haxx.se/docs/CVE-2020-8231.html">https://curl.haxx.se/docs/CVE-2020-8231.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8231">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8231</a>
          <a href="https://hackerone.com/reports/948876">https://hackerone.com/reports/948876</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8231.html">https://linux.oracle.com/cve/CVE-2020-8231.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8231">https://nvd.nist.gov/vuln/detail/CVE-2020-8231</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://ubuntu.com/security/notices/USN-4466-1">https://ubuntu.com/security/notices/USN-4466-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4466-2">https://ubuntu.com/security/notices/USN-4466-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2020-8285</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Apr/51">http://seclists.org/fulldisclosure/2021/Apr/51</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-8285">https://access.redhat.com/security/cve/CVE-2020-8285</a>
          <a href="https://curl.se/docs/CVE-2020-8285.html">https://curl.se/docs/CVE-2020-8285.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8285">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8285</a>
          <a href="https://github.com/curl/curl/issues/6255">https://github.com/curl/curl/issues/6255</a>
          <a href="https://hackerone.com/reports/1045844">https://hackerone.com/reports/1045844</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8285.html">https://linux.oracle.com/cve/CVE-2020-8285.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8285">https://nvd.nist.gov/vuln/detail/CVE-2020-8285</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://security.netapp.com/advisory/ntap-20210122-0007/">https://security.netapp.com/advisory/ntap-20210122-0007/</a>
          <a href="https://support.apple.com/kb/HT212325">https://support.apple.com/kb/HT212325</a>
          <a href="https://support.apple.com/kb/HT212326">https://support.apple.com/kb/HT212326</a>
          <a href="https://support.apple.com/kb/HT212327">https://support.apple.com/kb/HT212327</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-2">https://ubuntu.com/security/notices/USN-4665-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2020-8286</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Apr/50">http://seclists.org/fulldisclosure/2021/Apr/50</a>
          <a href="http://seclists.org/fulldisclosure/2021/Apr/51">http://seclists.org/fulldisclosure/2021/Apr/51</a>
          <a href="http://seclists.org/fulldisclosure/2021/Apr/54">http://seclists.org/fulldisclosure/2021/Apr/54</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-8286">https://access.redhat.com/security/cve/CVE-2020-8286</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-200951.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-200951.pdf</a>
          <a href="https://curl.se/docs/CVE-2020-8286.html">https://curl.se/docs/CVE-2020-8286.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8286">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8286</a>
          <a href="https://hackerone.com/reports/1048457">https://hackerone.com/reports/1048457</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8286.html">https://linux.oracle.com/cve/CVE-2020-8286.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8286">https://nvd.nist.gov/vuln/detail/CVE-2020-8286</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://security.netapp.com/advisory/ntap-20210122-0007/">https://security.netapp.com/advisory/ntap-20210122-0007/</a>
          <a href="https://support.apple.com/kb/HT212325">https://support.apple.com/kb/HT212325</a>
          <a href="https://support.apple.com/kb/HT212326">https://support.apple.com/kb/HT212326</a>
          <a href="https://support.apple.com/kb/HT212327">https://support.apple.com/kb/HT212327</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22946</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u16</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22946">https://access.redhat.com/security/cve/CVE-2021-22946</a>
          <a href="https://curl.se/docs/CVE-2021-22946.html">https://curl.se/docs/CVE-2021-22946.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946</a>
          <a href="https://hackerone.com/reports/1334111">https://hackerone.com/reports/1334111</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22946.html">https://linux.oracle.com/cve/CVE-2021-22946.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22946">https://nvd.nist.gov/vuln/detail/CVE-2021-22946</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22876</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u14</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22876">https://access.redhat.com/security/cve/CVE-2021-22876</a>
          <a href="https://curl.se/docs/CVE-2021-22876.html">https://curl.se/docs/CVE-2021-22876.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22876">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22876</a>
          <a href="https://hackerone.com/reports/1101882">https://hackerone.com/reports/1101882</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22876.html">https://linux.oracle.com/cve/CVE-2021-22876.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4511.html">https://linux.oracle.com/errata/ELSA-2021-4511.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/05/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/05/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2ZC5BMIOKLBQJSFCHEDN2G2C2SH274BP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2ZC5BMIOKLBQJSFCHEDN2G2C2SH274BP/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ITVWPVGLFISU5BJC2BXBRYSDXTXE2YGC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ITVWPVGLFISU5BJC2BXBRYSDXTXE2YGC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQUIOYX2KUU6FIUZVB5WWZ6JHSSYSQWJ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQUIOYX2KUU6FIUZVB5WWZ6JHSSYSQWJ/</a>
          <a href="https://security.gentoo.org/glsa/202105-36">https://security.gentoo.org/glsa/202105-36</a>
          <a href="https://security.netapp.com/advisory/ntap-20210521-0007/">https://security.netapp.com/advisory/ntap-20210521-0007/</a>
          <a href="https://ubuntu.com/security/notices/USN-4898-1">https://ubuntu.com/security/notices/USN-4898-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4903-1">https://ubuntu.com/security/notices/USN-4903-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u16</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22947">https://access.redhat.com/security/cve/CVE-2021-22947</a>
          <a href="https://curl.se/docs/CVE-2021-22947.html">https://curl.se/docs/CVE-2021-22947.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947</a>
          <a href="https://hackerone.com/reports/1334763">https://hackerone.com/reports/1334763</a>
          <a href="https://launchpad.net/bugs/1944120 (regression bug)">https://launchpad.net/bugs/1944120 (regression bug)</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22947.html">https://linux.oracle.com/cve/CVE-2021-22947.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22947">https://nvd.nist.gov/vuln/detail/CVE-2021-22947</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-3">https://ubuntu.com/security/notices/USN-5079-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-4">https://ubuntu.com/security/notices/USN-5079-4</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">dirmngr</td>
        <td>CVE-2018-1000858</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.18-8~deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000858">https://access.redhat.com/security/cve/CVE-2018-1000858</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858</a>
          <a href="https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html">https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html</a>
          <a href="https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html">https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html</a>
          <a href="https://ubuntu.com/security/notices/USN-3853-1">https://ubuntu.com/security/notices/USN-3853-1</a>
          <a href="https://usn.ubuntu.com/3853-1/">https://usn.ubuntu.com/3853-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gcc-6-base</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">6.3.0-18+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-12886">https://access.redhat.com/security/cve/CVE-2018-12886</a>
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gnupg</td>
        <td>CVE-2018-1000858</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.18-8~deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000858">https://access.redhat.com/security/cve/CVE-2018-1000858</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858</a>
          <a href="https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html">https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html</a>
          <a href="https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html">https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html</a>
          <a href="https://ubuntu.com/security/notices/USN-3853-1">https://ubuntu.com/security/notices/USN-3853-1</a>
          <a href="https://usn.ubuntu.com/3853-1/">https://usn.ubuntu.com/3853-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gnupg-agent</td>
        <td>CVE-2018-1000858</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.18-8~deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000858">https://access.redhat.com/security/cve/CVE-2018-1000858</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858</a>
          <a href="https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html">https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html</a>
          <a href="https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html">https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html</a>
          <a href="https://ubuntu.com/security/notices/USN-3853-1">https://ubuntu.com/security/notices/USN-3853-1</a>
          <a href="https://usn.ubuntu.com/3853-1/">https://usn.ubuntu.com/3853-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gpgv</td>
        <td>CVE-2018-1000858</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.18-8~deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000858">https://access.redhat.com/security/cve/CVE-2018-1000858</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000858</a>
          <a href="https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html">https://sektioneins.de/en/advisories/advisory-012018-gnupg-wkd.html</a>
          <a href="https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html">https://sektioneins.de/en/blog/18-11-23-gnupg-wkd.html</a>
          <a href="https://ubuntu.com/security/notices/USN-3853-1">https://ubuntu.com/security/notices/USN-3853-1</a>
          <a href="https://usn.ubuntu.com/3853-1/">https://usn.ubuntu.com/3853-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libapt-pkg5.0</td>
        <td>CVE-2020-27350</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.9</td>
        <td>1.4.11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27350">https://access.redhat.com/security/cve/CVE-2020-27350</a>
          <a href="https://bugs.launchpad.net/bugs/1899193">https://bugs.launchpad.net/bugs/1899193</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27350</a>
          <a href="https://security.netapp.com/advisory/ntap-20210108-0005/">https://security.netapp.com/advisory/ntap-20210108-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-4667-1">https://ubuntu.com/security/notices/USN-4667-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4667-2">https://ubuntu.com/security/notices/USN-4667-2</a>
          <a href="https://usn.ubuntu.com/usn/usn-4667-1">https://usn.ubuntu.com/usn/usn-4667-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4808">https://www.debian.org/security/2020/dsa-4808</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libapt-pkg5.0</td>
        <td>CVE-2020-3810</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.9</td>
        <td>1.4.10</td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.launchpad.net/bugs/1878177">https://bugs.launchpad.net/bugs/1878177</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810</a>
          <a href="https://github.com/Debian/apt/issues/111">https://github.com/Debian/apt/issues/111</a>
          <a href="https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36">https://github.com/julian-klode/apt/commit/de4efadc3c92e26d37272fd310be148ec61dcf36</a>
          <a href="https://lists.debian.org/debian-security-announce/2020/msg00089.html">https://lists.debian.org/debian-security-announce/2020/msg00089.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U4PEH357MZM2SUGKETMEHMSGQS652QHH/</a>
          <a href="https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6">https://salsa.debian.org/apt-team/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6</a>
          <a href="https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6">https://salsa.debian.org/jak/apt/-/commit/dceb1e49e4b8e4dadaf056be34088b415939cda6</a>
          <a href="https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/">https://tracker.debian.org/news/1144109/accepted-apt-212-source-into-unstable/</a>
          <a href="https://ubuntu.com/security/notices/USN-4359-1">https://ubuntu.com/security/notices/USN-4359-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4359-2">https://ubuntu.com/security/notices/USN-4359-2</a>
          <a href="https://usn.ubuntu.com/4359-1/">https://usn.ubuntu.com/4359-1/</a>
          <a href="https://usn.ubuntu.com/4359-2/">https://usn.ubuntu.com/4359-2/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libblkid1</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libbz2-1.0</td>
        <td>CVE-2019-12900</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.0.6-8.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00040.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00050.html">http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00050.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00078.html">http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00078.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00000.html">http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00000.html</a>
          <a href="http://packetstormsecurity.com/files/153644/Slackware-Security-Advisory-bzip2-Updates.html">http://packetstormsecurity.com/files/153644/Slackware-Security-Advisory-bzip2-Updates.html</a>
          <a href="http://packetstormsecurity.com/files/153957/FreeBSD-Security-Advisory-FreeBSD-SA-19-18.bzip2.html">http://packetstormsecurity.com/files/153957/FreeBSD-Security-Advisory-FreeBSD-SA-19-18.bzip2.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-12900">https://access.redhat.com/security/cve/CVE-2019-12900</a>
          <a href="https://bugs.launchpad.net/ubuntu/+source/bzip2/+bug/1834494">https://bugs.launchpad.net/ubuntu/+source/bzip2/+bug/1834494</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12900">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12900</a>
          <a href="https://gitlab.com/federicomenaquintero/bzip2/commit/74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc">https://gitlab.com/federicomenaquintero/bzip2/commit/74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc</a>
          <a href="https://lists.apache.org/thread.html/ra0adb9653c7de9539b93cc8434143b655f753b9f60580ff260becb2b@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/ra0adb9653c7de9539b93cc8434143b655f753b9f60580ff260becb2b@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rce8cd8c30f60604b580ea01bebda8a671a25c9a1629f409fc24e7774@%3Cuser.flink.apache.org%3E">https://lists.apache.org/thread.html/rce8cd8c30f60604b580ea01bebda8a671a25c9a1629f409fc24e7774@%3Cuser.flink.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rda98305669476c4d90cc8527c4deda7e449019dd1fe9936b56671dd4@%3Cuser.flink.apache.org%3E">https://lists.apache.org/thread.html/rda98305669476c4d90cc8527c4deda7e449019dd1fe9936b56671dd4@%3Cuser.flink.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/06/msg00021.html">https://lists.debian.org/debian-lts-announce/2019/06/msg00021.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2019/07/msg00014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/10/msg00012.html">https://lists.debian.org/debian-lts-announce/2019/10/msg00012.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/10/msg00018.html">https://lists.debian.org/debian-lts-announce/2019/10/msg00018.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-12900">https://nvd.nist.gov/vuln/detail/CVE-2019-12900</a>
          <a href="https://seclists.org/bugtraq/2019/Aug/4">https://seclists.org/bugtraq/2019/Aug/4</a>
          <a href="https://seclists.org/bugtraq/2019/Jul/22">https://seclists.org/bugtraq/2019/Jul/22</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-19:18.bzip2.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-19:18.bzip2.asc</a>
          <a href="https://support.f5.com/csp/article/K68713584?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K68713584?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4038-1">https://ubuntu.com/security/notices/USN-4038-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4038-2">https://ubuntu.com/security/notices/USN-4038-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4038-3">https://ubuntu.com/security/notices/USN-4038-3</a>
          <a href="https://ubuntu.com/security/notices/USN-4038-4">https://ubuntu.com/security/notices/USN-4038-4</a>
          <a href="https://ubuntu.com/security/notices/USN-4146-1">https://ubuntu.com/security/notices/USN-4146-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4146-2">https://ubuntu.com/security/notices/USN-4146-2</a>
          <a href="https://usn.ubuntu.com/4038-1/">https://usn.ubuntu.com/4038-1/</a>
          <a href="https://usn.ubuntu.com/4038-2/">https://usn.ubuntu.com/4038-2/</a>
          <a href="https://usn.ubuntu.com/4146-1/">https://usn.ubuntu.com/4146-1/</a>
          <a href="https://usn.ubuntu.com/4146-2/">https://usn.ubuntu.com/4146-2/</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2018-6485</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://bugs.debian.org/878159">http://bugs.debian.org/878159</a>
          <a href="http://www.securityfocus.com/bid/102912">http://www.securityfocus.com/bid/102912</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3092">https://access.redhat.com/errata/RHSA-2018:3092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-6485">https://access.redhat.com/security/cve/CVE-2018-6485</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-6485.html">https://linux.oracle.com/cve/CVE-2018-6485.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3092.html">https://linux.oracle.com/errata/ELSA-2018-3092.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22343">https://sourceware.org/bugzilla/show_bug.cgi?id=22343</a>
          <a href="https://ubuntu.com/security/notices/USN-4218-1">https://ubuntu.com/security/notices/USN-4218-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4218-1/">https://usn.ubuntu.com/4218-1/</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html">https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2018-6551</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-6551">https://access.redhat.com/security/cve/CVE-2018-6551</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22774">https://sourceware.org/bugzilla/show_bug.cgi?id=22774</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22">https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2019-9169</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/107160">http://www.securityfocus.com/bid/107160</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9169">https://access.redhat.com/security/cve/CVE-2019-9169</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9169.html">https://linux.oracle.com/cve/CVE-2019-9169.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9169">https://nvd.nist.gov/vuln/detail/CVE-2019-9169</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24114">https://sourceware.org/bugzilla/show_bug.cgi?id=24114</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9</a>
          <a href="https://support.f5.com/csp/article/K54823184">https://support.f5.com/csp/article/K54823184</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33574">https://access.redhat.com/security/cve/CVE-2021-33574</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33574">https://nvd.nist.gov/vuln/detail/CVE-2021-33574</a>
          <a href="https://security.gentoo.org/glsa/202107-07">https://security.gentoo.org/glsa/202107-07</a>
          <a href="https://security.netapp.com/advisory/ntap-20210629-0005/">https://security.netapp.com/advisory/ntap-20210629-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896">https://sourceware.org/bugzilla/show_bug.cgi?id=27896</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1">https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-35942</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-35942">https://access.redhat.com/security/cve/CVE-2021-35942</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35942">https://nvd.nist.gov/vuln/detail/CVE-2021-35942</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0005/">https://security.netapp.com/advisory/ntap-20210827-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28011">https://sourceware.org/bugzilla/show_bug.cgi?id=28011</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c">https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c</a>
          <a href="https://sourceware.org/glibc/wiki/Security%20Exceptions">https://sourceware.org/glibc/wiki/Security%20Exceptions</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2022-23218</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2009-5155</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272">http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272</a>
          <a href="https://access.redhat.com/security/cve/CVE-2009-5155">https://access.redhat.com/security/cve/CVE-2009-5155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=11053">https://sourceware.org/bugzilla/show_bug.cgi?id=11053</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18986">https://sourceware.org/bugzilla/show_bug.cgi?id=18986</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672</a>
          <a href="https://support.f5.com/csp/article/K64119434">https://support.f5.com/csp/article/K64119434</a>
          <a href="https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4954-1">https://ubuntu.com/security/notices/USN-4954-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2018-1000001</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2018/q1/38">http://seclists.org/oss-sec/2018/q1/38</a>
          <a href="http://www.openwall.com/lists/oss-security/2018/01/11/5">http://www.openwall.com/lists/oss-security/2018/01/11/5</a>
          <a href="http://www.securityfocus.com/bid/102525">http://www.securityfocus.com/bid/102525</a>
          <a href="http://www.securitytracker.com/id/1040162">http://www.securitytracker.com/id/1040162</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000001">https://access.redhat.com/security/cve/CVE-2018-1000001</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-1000001.html">https://linux.oracle.com/cve/CVE-2018-1000001.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://lists.samba.org/archive/rsync/2018-February/031478.html">https://lists.samba.org/archive/rsync/2018-February/031478.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18203">https://sourceware.org/bugzilla/show_bug.cgi?id=18203</a>
          <a href="https://ubuntu.com/security/notices/USN-3534-1">https://ubuntu.com/security/notices/USN-3534-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3536-1">https://ubuntu.com/security/notices/USN-3536-1</a>
          <a href="https://usn.ubuntu.com/3534-1/">https://usn.ubuntu.com/3534-1/</a>
          <a href="https://usn.ubuntu.com/3536-1/">https://usn.ubuntu.com/3536-1/</a>
          <a href="https://www.exploit-db.com/exploits/43775/">https://www.exploit-db.com/exploits/43775/</a>
          <a href="https://www.exploit-db.com/exploits/44889/">https://www.exploit-db.com/exploits/44889/</a>
          <a href="https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/">https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1751">https://access.redhat.com/security/cve/CVE-2020-1751</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1751">https://nvd.nist.gov/vuln/detail/CVE-2020-1751</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200430-0002/">https://security.netapp.com/advisory/ntap-20200430-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25423">https://sourceware.org/bugzilla/show_bug.cgi?id=25423</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-1752</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1752">https://access.redhat.com/security/cve/CVE-2020-1752</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1752">https://nvd.nist.gov/vuln/detail/CVE-2020-1752</a>
          <a href="https://security.gentoo.org/glsa/202101-20">https://security.gentoo.org/glsa/202101-20</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0005/">https://security.netapp.com/advisory/ntap-20200511-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25414">https://sourceware.org/bugzilla/show_bug.cgi?id=25414</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-3326</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3326">https://access.redhat.com/security/cve/CVE-2021-3326</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3326">https://nvd.nist.gov/vuln/detail/CVE-2021-3326</a>
          <a href="https://security.netapp.com/advisory/ntap-20210304-0007/">https://security.netapp.com/advisory/ntap-20210304-0007/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27256">https://sourceware.org/bugzilla/show_bug.cgi?id=27256</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888">https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888</a>
          <a href="https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html">https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-3999</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2016-10739</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html</a>
          <a href="http://www.securityfocus.com/bid/106672">http://www.securityfocus.com/bid/106672</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2118">https://access.redhat.com/errata/RHSA-2019:2118</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3513">https://access.redhat.com/errata/RHSA-2019:3513</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-10739">https://access.redhat.com/security/cve/CVE-2016-10739</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1347549">https://bugzilla.redhat.com/show_bug.cgi?id=1347549</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739</a>
          <a href="https://linux.oracle.com/cve/CVE-2016-10739.html">https://linux.oracle.com/cve/CVE-2016-10739.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3513.html">https://linux.oracle.com/errata/ELSA-2019-3513.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-10739">https://nvd.nist.gov/vuln/detail/CVE-2016-10739</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=20018">https://sourceware.org/bugzilla/show_bug.cgi?id=20018</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2017-12132</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/100598">http://www.securityfocus.com/bid/100598</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-12132">https://access.redhat.com/security/cve/CVE-2017-12132</a>
          <a href="https://arxiv.org/pdf/1205.4011.pdf">https://arxiv.org/pdf/1205.4011.pdf</a>
          <a href="https://linux.oracle.com/cve/CVE-2017-12132.html">https://linux.oracle.com/cve/CVE-2017-12132.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=21361">https://sourceware.org/bugzilla/show_bug.cgi?id=21361</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-25013">https://access.redhat.com/security/cve/CVE-2019-25013</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-25013.html">https://linux.oracle.com/cve/CVE-2019-25013.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-25013">https://nvd.nist.gov/vuln/detail/CVE-2019-25013</a>
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10029">https://access.redhat.com/security/cve/CVE-2020-10029</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10029">https://nvd.nist.gov/vuln/detail/CVE-2020-10029</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200327-0003/">https://security.netapp.com/advisory/ntap-20200327-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25487">https://sourceware.org/bugzilla/show_bug.cgi?id=25487</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-27618</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27618">https://access.redhat.com/security/cve/CVE-2020-27618</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-27618">https://nvd.nist.gov/vuln/detail/CVE-2020-27618</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3998">https://access.redhat.com/security/cve/CVE-2021-3998</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2018-6485</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://bugs.debian.org/878159">http://bugs.debian.org/878159</a>
          <a href="http://www.securityfocus.com/bid/102912">http://www.securityfocus.com/bid/102912</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3092">https://access.redhat.com/errata/RHSA-2018:3092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-6485">https://access.redhat.com/security/cve/CVE-2018-6485</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-6485.html">https://linux.oracle.com/cve/CVE-2018-6485.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3092.html">https://linux.oracle.com/errata/ELSA-2018-3092.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22343">https://sourceware.org/bugzilla/show_bug.cgi?id=22343</a>
          <a href="https://ubuntu.com/security/notices/USN-4218-1">https://ubuntu.com/security/notices/USN-4218-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4218-1/">https://usn.ubuntu.com/4218-1/</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html">https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2018-6551</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-6551">https://access.redhat.com/security/cve/CVE-2018-6551</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22774">https://sourceware.org/bugzilla/show_bug.cgi?id=22774</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22">https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2019-9169</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/107160">http://www.securityfocus.com/bid/107160</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9169">https://access.redhat.com/security/cve/CVE-2019-9169</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9169.html">https://linux.oracle.com/cve/CVE-2019-9169.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9169">https://nvd.nist.gov/vuln/detail/CVE-2019-9169</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24114">https://sourceware.org/bugzilla/show_bug.cgi?id=24114</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9</a>
          <a href="https://support.f5.com/csp/article/K54823184">https://support.f5.com/csp/article/K54823184</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33574">https://access.redhat.com/security/cve/CVE-2021-33574</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33574">https://nvd.nist.gov/vuln/detail/CVE-2021-33574</a>
          <a href="https://security.gentoo.org/glsa/202107-07">https://security.gentoo.org/glsa/202107-07</a>
          <a href="https://security.netapp.com/advisory/ntap-20210629-0005/">https://security.netapp.com/advisory/ntap-20210629-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896">https://sourceware.org/bugzilla/show_bug.cgi?id=27896</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1">https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2021-35942</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-35942">https://access.redhat.com/security/cve/CVE-2021-35942</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35942">https://nvd.nist.gov/vuln/detail/CVE-2021-35942</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0005/">https://security.netapp.com/advisory/ntap-20210827-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28011">https://sourceware.org/bugzilla/show_bug.cgi?id=28011</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c">https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c</a>
          <a href="https://sourceware.org/glibc/wiki/Security%20Exceptions">https://sourceware.org/glibc/wiki/Security%20Exceptions</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2022-23218</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2009-5155</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272">http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272</a>
          <a href="https://access.redhat.com/security/cve/CVE-2009-5155">https://access.redhat.com/security/cve/CVE-2009-5155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=11053">https://sourceware.org/bugzilla/show_bug.cgi?id=11053</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18986">https://sourceware.org/bugzilla/show_bug.cgi?id=18986</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672</a>
          <a href="https://support.f5.com/csp/article/K64119434">https://support.f5.com/csp/article/K64119434</a>
          <a href="https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4954-1">https://ubuntu.com/security/notices/USN-4954-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2018-1000001</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2018/q1/38">http://seclists.org/oss-sec/2018/q1/38</a>
          <a href="http://www.openwall.com/lists/oss-security/2018/01/11/5">http://www.openwall.com/lists/oss-security/2018/01/11/5</a>
          <a href="http://www.securityfocus.com/bid/102525">http://www.securityfocus.com/bid/102525</a>
          <a href="http://www.securitytracker.com/id/1040162">http://www.securitytracker.com/id/1040162</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000001">https://access.redhat.com/security/cve/CVE-2018-1000001</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-1000001.html">https://linux.oracle.com/cve/CVE-2018-1000001.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://lists.samba.org/archive/rsync/2018-February/031478.html">https://lists.samba.org/archive/rsync/2018-February/031478.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18203">https://sourceware.org/bugzilla/show_bug.cgi?id=18203</a>
          <a href="https://ubuntu.com/security/notices/USN-3534-1">https://ubuntu.com/security/notices/USN-3534-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3536-1">https://ubuntu.com/security/notices/USN-3536-1</a>
          <a href="https://usn.ubuntu.com/3534-1/">https://usn.ubuntu.com/3534-1/</a>
          <a href="https://usn.ubuntu.com/3536-1/">https://usn.ubuntu.com/3536-1/</a>
          <a href="https://www.exploit-db.com/exploits/43775/">https://www.exploit-db.com/exploits/43775/</a>
          <a href="https://www.exploit-db.com/exploits/44889/">https://www.exploit-db.com/exploits/44889/</a>
          <a href="https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/">https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1751">https://access.redhat.com/security/cve/CVE-2020-1751</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1751">https://nvd.nist.gov/vuln/detail/CVE-2020-1751</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200430-0002/">https://security.netapp.com/advisory/ntap-20200430-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25423">https://sourceware.org/bugzilla/show_bug.cgi?id=25423</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2020-1752</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1752">https://access.redhat.com/security/cve/CVE-2020-1752</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1752">https://nvd.nist.gov/vuln/detail/CVE-2020-1752</a>
          <a href="https://security.gentoo.org/glsa/202101-20">https://security.gentoo.org/glsa/202101-20</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0005/">https://security.netapp.com/advisory/ntap-20200511-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25414">https://sourceware.org/bugzilla/show_bug.cgi?id=25414</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2021-3326</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3326">https://access.redhat.com/security/cve/CVE-2021-3326</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3326">https://nvd.nist.gov/vuln/detail/CVE-2021-3326</a>
          <a href="https://security.netapp.com/advisory/ntap-20210304-0007/">https://security.netapp.com/advisory/ntap-20210304-0007/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27256">https://sourceware.org/bugzilla/show_bug.cgi?id=27256</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888">https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888</a>
          <a href="https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html">https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2021-3999</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2016-10739</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html</a>
          <a href="http://www.securityfocus.com/bid/106672">http://www.securityfocus.com/bid/106672</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2118">https://access.redhat.com/errata/RHSA-2019:2118</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3513">https://access.redhat.com/errata/RHSA-2019:3513</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-10739">https://access.redhat.com/security/cve/CVE-2016-10739</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1347549">https://bugzilla.redhat.com/show_bug.cgi?id=1347549</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739</a>
          <a href="https://linux.oracle.com/cve/CVE-2016-10739.html">https://linux.oracle.com/cve/CVE-2016-10739.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3513.html">https://linux.oracle.com/errata/ELSA-2019-3513.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-10739">https://nvd.nist.gov/vuln/detail/CVE-2016-10739</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=20018">https://sourceware.org/bugzilla/show_bug.cgi?id=20018</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2017-12132</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/100598">http://www.securityfocus.com/bid/100598</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-12132">https://access.redhat.com/security/cve/CVE-2017-12132</a>
          <a href="https://arxiv.org/pdf/1205.4011.pdf">https://arxiv.org/pdf/1205.4011.pdf</a>
          <a href="https://linux.oracle.com/cve/CVE-2017-12132.html">https://linux.oracle.com/cve/CVE-2017-12132.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=21361">https://sourceware.org/bugzilla/show_bug.cgi?id=21361</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-25013">https://access.redhat.com/security/cve/CVE-2019-25013</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-25013.html">https://linux.oracle.com/cve/CVE-2019-25013.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-25013">https://nvd.nist.gov/vuln/detail/CVE-2019-25013</a>
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10029">https://access.redhat.com/security/cve/CVE-2020-10029</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10029">https://nvd.nist.gov/vuln/detail/CVE-2020-10029</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200327-0003/">https://security.netapp.com/advisory/ntap-20200327-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25487">https://sourceware.org/bugzilla/show_bug.cgi?id=25487</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2020-27618</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27618">https://access.redhat.com/security/cve/CVE-2020-27618</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-27618">https://nvd.nist.gov/vuln/detail/CVE-2020-27618</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-l10n</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3998">https://access.redhat.com/security/cve/CVE-2021-3998</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2018-6485</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://bugs.debian.org/878159">http://bugs.debian.org/878159</a>
          <a href="http://www.securityfocus.com/bid/102912">http://www.securityfocus.com/bid/102912</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3092">https://access.redhat.com/errata/RHSA-2018:3092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-6485">https://access.redhat.com/security/cve/CVE-2018-6485</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-6485.html">https://linux.oracle.com/cve/CVE-2018-6485.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3092.html">https://linux.oracle.com/errata/ELSA-2018-3092.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22343">https://sourceware.org/bugzilla/show_bug.cgi?id=22343</a>
          <a href="https://ubuntu.com/security/notices/USN-4218-1">https://ubuntu.com/security/notices/USN-4218-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4218-1/">https://usn.ubuntu.com/4218-1/</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html">https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2018-6551</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-6551">https://access.redhat.com/security/cve/CVE-2018-6551</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22774">https://sourceware.org/bugzilla/show_bug.cgi?id=22774</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22">https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2019-9169</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/107160">http://www.securityfocus.com/bid/107160</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9169">https://access.redhat.com/security/cve/CVE-2019-9169</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9169.html">https://linux.oracle.com/cve/CVE-2019-9169.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9169">https://nvd.nist.gov/vuln/detail/CVE-2019-9169</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24114">https://sourceware.org/bugzilla/show_bug.cgi?id=24114</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9</a>
          <a href="https://support.f5.com/csp/article/K54823184">https://support.f5.com/csp/article/K54823184</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33574">https://access.redhat.com/security/cve/CVE-2021-33574</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33574">https://nvd.nist.gov/vuln/detail/CVE-2021-33574</a>
          <a href="https://security.gentoo.org/glsa/202107-07">https://security.gentoo.org/glsa/202107-07</a>
          <a href="https://security.netapp.com/advisory/ntap-20210629-0005/">https://security.netapp.com/advisory/ntap-20210629-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896">https://sourceware.org/bugzilla/show_bug.cgi?id=27896</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1">https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-35942</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-35942">https://access.redhat.com/security/cve/CVE-2021-35942</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35942">https://nvd.nist.gov/vuln/detail/CVE-2021-35942</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0005/">https://security.netapp.com/advisory/ntap-20210827-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28011">https://sourceware.org/bugzilla/show_bug.cgi?id=28011</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c">https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c</a>
          <a href="https://sourceware.org/glibc/wiki/Security%20Exceptions">https://sourceware.org/glibc/wiki/Security%20Exceptions</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2022-23218</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2009-5155</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272">http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272</a>
          <a href="https://access.redhat.com/security/cve/CVE-2009-5155">https://access.redhat.com/security/cve/CVE-2009-5155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=11053">https://sourceware.org/bugzilla/show_bug.cgi?id=11053</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18986">https://sourceware.org/bugzilla/show_bug.cgi?id=18986</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672</a>
          <a href="https://support.f5.com/csp/article/K64119434">https://support.f5.com/csp/article/K64119434</a>
          <a href="https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4954-1">https://ubuntu.com/security/notices/USN-4954-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2018-1000001</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2018/q1/38">http://seclists.org/oss-sec/2018/q1/38</a>
          <a href="http://www.openwall.com/lists/oss-security/2018/01/11/5">http://www.openwall.com/lists/oss-security/2018/01/11/5</a>
          <a href="http://www.securityfocus.com/bid/102525">http://www.securityfocus.com/bid/102525</a>
          <a href="http://www.securitytracker.com/id/1040162">http://www.securitytracker.com/id/1040162</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000001">https://access.redhat.com/security/cve/CVE-2018-1000001</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-1000001.html">https://linux.oracle.com/cve/CVE-2018-1000001.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://lists.samba.org/archive/rsync/2018-February/031478.html">https://lists.samba.org/archive/rsync/2018-February/031478.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18203">https://sourceware.org/bugzilla/show_bug.cgi?id=18203</a>
          <a href="https://ubuntu.com/security/notices/USN-3534-1">https://ubuntu.com/security/notices/USN-3534-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3536-1">https://ubuntu.com/security/notices/USN-3536-1</a>
          <a href="https://usn.ubuntu.com/3534-1/">https://usn.ubuntu.com/3534-1/</a>
          <a href="https://usn.ubuntu.com/3536-1/">https://usn.ubuntu.com/3536-1/</a>
          <a href="https://www.exploit-db.com/exploits/43775/">https://www.exploit-db.com/exploits/43775/</a>
          <a href="https://www.exploit-db.com/exploits/44889/">https://www.exploit-db.com/exploits/44889/</a>
          <a href="https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/">https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1751">https://access.redhat.com/security/cve/CVE-2020-1751</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1751">https://nvd.nist.gov/vuln/detail/CVE-2020-1751</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200430-0002/">https://security.netapp.com/advisory/ntap-20200430-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25423">https://sourceware.org/bugzilla/show_bug.cgi?id=25423</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-1752</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1752">https://access.redhat.com/security/cve/CVE-2020-1752</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1752">https://nvd.nist.gov/vuln/detail/CVE-2020-1752</a>
          <a href="https://security.gentoo.org/glsa/202101-20">https://security.gentoo.org/glsa/202101-20</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0005/">https://security.netapp.com/advisory/ntap-20200511-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25414">https://sourceware.org/bugzilla/show_bug.cgi?id=25414</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-3326</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3326">https://access.redhat.com/security/cve/CVE-2021-3326</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3326">https://nvd.nist.gov/vuln/detail/CVE-2021-3326</a>
          <a href="https://security.netapp.com/advisory/ntap-20210304-0007/">https://security.netapp.com/advisory/ntap-20210304-0007/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27256">https://sourceware.org/bugzilla/show_bug.cgi?id=27256</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888">https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888</a>
          <a href="https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html">https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-3999</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2016-10739</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html</a>
          <a href="http://www.securityfocus.com/bid/106672">http://www.securityfocus.com/bid/106672</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2118">https://access.redhat.com/errata/RHSA-2019:2118</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3513">https://access.redhat.com/errata/RHSA-2019:3513</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-10739">https://access.redhat.com/security/cve/CVE-2016-10739</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1347549">https://bugzilla.redhat.com/show_bug.cgi?id=1347549</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739</a>
          <a href="https://linux.oracle.com/cve/CVE-2016-10739.html">https://linux.oracle.com/cve/CVE-2016-10739.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3513.html">https://linux.oracle.com/errata/ELSA-2019-3513.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-10739">https://nvd.nist.gov/vuln/detail/CVE-2016-10739</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=20018">https://sourceware.org/bugzilla/show_bug.cgi?id=20018</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2017-12132</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/100598">http://www.securityfocus.com/bid/100598</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-12132">https://access.redhat.com/security/cve/CVE-2017-12132</a>
          <a href="https://arxiv.org/pdf/1205.4011.pdf">https://arxiv.org/pdf/1205.4011.pdf</a>
          <a href="https://linux.oracle.com/cve/CVE-2017-12132.html">https://linux.oracle.com/cve/CVE-2017-12132.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=21361">https://sourceware.org/bugzilla/show_bug.cgi?id=21361</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-25013">https://access.redhat.com/security/cve/CVE-2019-25013</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-25013.html">https://linux.oracle.com/cve/CVE-2019-25013.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-25013">https://nvd.nist.gov/vuln/detail/CVE-2019-25013</a>
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10029">https://access.redhat.com/security/cve/CVE-2020-10029</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10029">https://nvd.nist.gov/vuln/detail/CVE-2020-10029</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200327-0003/">https://security.netapp.com/advisory/ntap-20200327-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25487">https://sourceware.org/bugzilla/show_bug.cgi?id=25487</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-27618</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27618">https://access.redhat.com/security/cve/CVE-2020-27618</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-27618">https://nvd.nist.gov/vuln/detail/CVE-2020-27618</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3998">https://access.redhat.com/security/cve/CVE-2021-3998</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcomerr2</td>
        <td>CVE-2019-5188</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.43.4-2+deb9u1</td>
        <td>1.43.4-2+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html">http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5188">https://access.redhat.com/security/cve/CVE-2019-5188</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5188.html">https://linux.oracle.com/cve/CVE-2019-5188.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4011.html">https://linux.oracle.com/errata/ELSA-2020-4011.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html">https://lists.debian.org/debian-lts-announce/2020/03/msg00030.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00021.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2AKETJ6BREDUHRWQTV35SPGG5C6H7KSI/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6DOBCYQKCTTWXBLMUPJ5TX3FY7JNCOKY/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-5188">https://nvd.nist.gov/vuln/detail/CVE-2019-5188</a>
          <a href="https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973">https://talosintelligence.com/vulnerability_reports/TALOS-2019-0973</a>
          <a href="https://ubuntu.com/security/notices/USN-4249-1">https://ubuntu.com/security/notices/USN-4249-1</a>
          <a href="https://usn.ubuntu.com/4249-1/">https://usn.ubuntu.com/4249-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2019-5481</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5481">https://access.redhat.com/security/cve/CVE-2019-5481</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5481.html">https://curl.haxx.se/docs/CVE-2019-5481.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5481">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5481</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5481.html">https://linux.oracle.com/cve/CVE-2019-5481.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1792.html">https://linux.oracle.com/errata/ELSA-2020-1792.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20191004-0003/">https://security.netapp.com/advisory/ntap-20191004-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-1">https://ubuntu.com/security/notices/USN-4129-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2019-5482</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00048.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5482">https://access.redhat.com/security/cve/CVE-2019-5482</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5482.html">https://curl.haxx.se/docs/CVE-2019-5482.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5482">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5482</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5482.html">https://linux.oracle.com/cve/CVE-2019-5482.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5562.html">https://linux.oracle.com/errata/ELSA-2020-5562.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6CI4QQ2RSZX4VCFM76SIWGKY6BY7UWIC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RGDVKSLY5JUNJRLYRUA6CXGQ2LM63XC3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UA7KDM2WPM5CJDDGOEGFV6SSGD2J7RNT/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20191004-0003/">https://security.netapp.com/advisory/ntap-20191004-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200416-0003/">https://security.netapp.com/advisory/ntap-20200416-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-1">https://ubuntu.com/security/notices/USN-4129-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4129-2">https://ubuntu.com/security/notices/USN-4129-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2019-5436</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u10</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00008.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00008.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00017.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00017.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/09/11/6">http://www.openwall.com/lists/oss-security/2019/09/11/6</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5436">https://access.redhat.com/security/cve/CVE-2019-5436</a>
          <a href="https://curl.haxx.se/docs/CVE-2019-5436.html">https://curl.haxx.se/docs/CVE-2019-5436.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5436">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5436</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5436.html">https://linux.oracle.com/cve/CVE-2019-5436.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1792.html">https://linux.oracle.com/errata/ELSA-2020-1792.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SMG3V4VTX2SE3EW3HQTN3DDLQBTORQC2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SMG3V4VTX2SE3EW3HQTN3DDLQBTORQC2/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/36">https://seclists.org/bugtraq/2020/Feb/36</a>
          <a href="https://security.gentoo.org/glsa/202003-29">https://security.gentoo.org/glsa/202003-29</a>
          <a href="https://security.netapp.com/advisory/ntap-20190606-0004/">https://security.netapp.com/advisory/ntap-20190606-0004/</a>
          <a href="https://support.f5.com/csp/article/K55133295">https://support.f5.com/csp/article/K55133295</a>
          <a href="https://support.f5.com/csp/article/K55133295?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K55133295?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-3993-1">https://ubuntu.com/security/notices/USN-3993-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3993-2">https://ubuntu.com/security/notices/USN-3993-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4633">https://www.debian.org/security/2020/dsa-4633</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2020-8177</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8177">https://access.redhat.com/security/cve/CVE-2020-8177</a>
          <a href="https://curl.haxx.se/docs/CVE-2020-8177.html">https://curl.haxx.se/docs/CVE-2020-8177.html</a>
          <a href="https://curl.se/docs/CVE-2020-8177.html">https://curl.se/docs/CVE-2020-8177.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8177">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8177</a>
          <a href="https://hackerone.com/reports/887462">https://hackerone.com/reports/887462</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8177.html">https://linux.oracle.com/cve/CVE-2020-8177.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5002.html">https://linux.oracle.com/errata/ELSA-2020-5002.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8177">https://nvd.nist.gov/vuln/detail/CVE-2020-8177</a>
          <a href="https://ubuntu.com/security/notices/USN-4402-1">https://ubuntu.com/security/notices/USN-4402-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2020-8231</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u12</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8231">https://access.redhat.com/security/cve/CVE-2020-8231</a>
          <a href="https://curl.haxx.se/docs/CVE-2020-8231.html">https://curl.haxx.se/docs/CVE-2020-8231.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8231">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8231</a>
          <a href="https://hackerone.com/reports/948876">https://hackerone.com/reports/948876</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8231.html">https://linux.oracle.com/cve/CVE-2020-8231.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8231">https://nvd.nist.gov/vuln/detail/CVE-2020-8231</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://ubuntu.com/security/notices/USN-4466-1">https://ubuntu.com/security/notices/USN-4466-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4466-2">https://ubuntu.com/security/notices/USN-4466-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2020-8285</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Apr/51">http://seclists.org/fulldisclosure/2021/Apr/51</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-8285">https://access.redhat.com/security/cve/CVE-2020-8285</a>
          <a href="https://curl.se/docs/CVE-2020-8285.html">https://curl.se/docs/CVE-2020-8285.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8285">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8285</a>
          <a href="https://github.com/curl/curl/issues/6255">https://github.com/curl/curl/issues/6255</a>
          <a href="https://hackerone.com/reports/1045844">https://hackerone.com/reports/1045844</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8285.html">https://linux.oracle.com/cve/CVE-2020-8285.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8285">https://nvd.nist.gov/vuln/detail/CVE-2020-8285</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://security.netapp.com/advisory/ntap-20210122-0007/">https://security.netapp.com/advisory/ntap-20210122-0007/</a>
          <a href="https://support.apple.com/kb/HT212325">https://support.apple.com/kb/HT212325</a>
          <a href="https://support.apple.com/kb/HT212326">https://support.apple.com/kb/HT212326</a>
          <a href="https://support.apple.com/kb/HT212327">https://support.apple.com/kb/HT212327</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-2">https://ubuntu.com/security/notices/USN-4665-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2020-8286</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Apr/50">http://seclists.org/fulldisclosure/2021/Apr/50</a>
          <a href="http://seclists.org/fulldisclosure/2021/Apr/51">http://seclists.org/fulldisclosure/2021/Apr/51</a>
          <a href="http://seclists.org/fulldisclosure/2021/Apr/54">http://seclists.org/fulldisclosure/2021/Apr/54</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-8286">https://access.redhat.com/security/cve/CVE-2020-8286</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-200951.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-200951.pdf</a>
          <a href="https://curl.se/docs/CVE-2020-8286.html">https://curl.se/docs/CVE-2020-8286.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8286">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8286</a>
          <a href="https://hackerone.com/reports/1048457">https://hackerone.com/reports/1048457</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8286.html">https://linux.oracle.com/cve/CVE-2020-8286.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1610.html">https://linux.oracle.com/errata/ELSA-2021-1610.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DAEHE2S2QLO4AO4MEEYL75NB7SAH5PSL/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8286">https://nvd.nist.gov/vuln/detail/CVE-2020-8286</a>
          <a href="https://security.gentoo.org/glsa/202012-14">https://security.gentoo.org/glsa/202012-14</a>
          <a href="https://security.netapp.com/advisory/ntap-20210122-0007/">https://security.netapp.com/advisory/ntap-20210122-0007/</a>
          <a href="https://support.apple.com/kb/HT212325">https://support.apple.com/kb/HT212325</a>
          <a href="https://support.apple.com/kb/HT212326">https://support.apple.com/kb/HT212326</a>
          <a href="https://support.apple.com/kb/HT212327">https://support.apple.com/kb/HT212327</a>
          <a href="https://ubuntu.com/security/notices/USN-4665-1">https://ubuntu.com/security/notices/USN-4665-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4881">https://www.debian.org/security/2021/dsa-4881</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2021-22946</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u16</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22946">https://access.redhat.com/security/cve/CVE-2021-22946</a>
          <a href="https://curl.se/docs/CVE-2021-22946.html">https://curl.se/docs/CVE-2021-22946.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946</a>
          <a href="https://hackerone.com/reports/1334111">https://hackerone.com/reports/1334111</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22946.html">https://linux.oracle.com/cve/CVE-2021-22946.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22946">https://nvd.nist.gov/vuln/detail/CVE-2021-22946</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2021-22876</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u14</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22876">https://access.redhat.com/security/cve/CVE-2021-22876</a>
          <a href="https://curl.se/docs/CVE-2021-22876.html">https://curl.se/docs/CVE-2021-22876.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22876">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22876</a>
          <a href="https://hackerone.com/reports/1101882">https://hackerone.com/reports/1101882</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22876.html">https://linux.oracle.com/cve/CVE-2021-22876.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4511.html">https://linux.oracle.com/errata/ELSA-2021-4511.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/05/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/05/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2ZC5BMIOKLBQJSFCHEDN2G2C2SH274BP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2ZC5BMIOKLBQJSFCHEDN2G2C2SH274BP/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ITVWPVGLFISU5BJC2BXBRYSDXTXE2YGC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ITVWPVGLFISU5BJC2BXBRYSDXTXE2YGC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQUIOYX2KUU6FIUZVB5WWZ6JHSSYSQWJ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQUIOYX2KUU6FIUZVB5WWZ6JHSSYSQWJ/</a>
          <a href="https://security.gentoo.org/glsa/202105-36">https://security.gentoo.org/glsa/202105-36</a>
          <a href="https://security.netapp.com/advisory/ntap-20210521-0007/">https://security.netapp.com/advisory/ntap-20210521-0007/</a>
          <a href="https://ubuntu.com/security/notices/USN-4898-1">https://ubuntu.com/security/notices/USN-4898-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4903-1">https://ubuntu.com/security/notices/USN-4903-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl3</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.52.1-5+deb9u9</td>
        <td>7.52.1-5+deb9u16</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22947">https://access.redhat.com/security/cve/CVE-2021-22947</a>
          <a href="https://curl.se/docs/CVE-2021-22947.html">https://curl.se/docs/CVE-2021-22947.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947</a>
          <a href="https://hackerone.com/reports/1334763">https://hackerone.com/reports/1334763</a>
          <a href="https://launchpad.net/bugs/1944120 (regression bug)">https://launchpad.net/bugs/1944120 (regression bug)</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22947.html">https://linux.oracle.com/cve/CVE-2021-22947.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22947">https://nvd.nist.gov/vuln/detail/CVE-2021-22947</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-3">https://ubuntu.com/security/notices/USN-5079-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-4">https://ubuntu.com/security/notices/USN-5079-4</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libfdisk1</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgcc1</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">6.3.0-18+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-12886">https://access.redhat.com/security/cve/CVE-2018-12886</a>
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2021-33560</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.7.6-2+deb9u3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33560.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33560.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-33560">https://access.redhat.com/security/cve/CVE-2021-33560</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33560">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33560</a>
          <a href="https://dev.gnupg.org/T5305">https://dev.gnupg.org/T5305</a>
          <a href="https://dev.gnupg.org/T5328">https://dev.gnupg.org/T5328</a>
          <a href="https://dev.gnupg.org/T5466">https://dev.gnupg.org/T5466</a>
          <a href="https://dev.gnupg.org/rCe8b7f10be275bcedb5fc05ed4837a89bfd605c61">https://dev.gnupg.org/rCe8b7f10be275bcedb5fc05ed4837a89bfd605c61</a>
          <a href="https://eprint.iacr.org/2021/923">https://eprint.iacr.org/2021/923</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33560.html">https://linux.oracle.com/cve/CVE-2021-33560.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4409.html">https://linux.oracle.com/errata/ELSA-2021-4409.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00021.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00021.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BKKTOIGFW2SGN3DO2UHHVZ7MJSYN4AAB/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BKKTOIGFW2SGN3DO2UHHVZ7MJSYN4AAB/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R7OAPCUGPF3VLA7QAJUQSL255D4ITVTL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R7OAPCUGPF3VLA7QAJUQSL255D4ITVTL/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33560">https://nvd.nist.gov/vuln/detail/CVE-2021-33560</a>
          <a href="https://ubuntu.com/security/notices/USN-5080-1">https://ubuntu.com/security/notices/USN-5080-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5080-2">https://ubuntu.com/security/notices/USN-5080-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2019-13627</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.7.6-2+deb9u3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html">http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/10/02/2">http://www.openwall.com/lists/oss-security/2019/10/02/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-13627">https://access.redhat.com/security/cve/CVE-2019-13627</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13627">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13627</a>
          <a href="https://dev.gnupg.org/T4683">https://dev.gnupg.org/T4683</a>
          <a href="https://github.com/gpg/libgcrypt/releases/tag/libgcrypt-1.8.5">https://github.com/gpg/libgcrypt/releases/tag/libgcrypt-1.8.5</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-13627.html">https://linux.oracle.com/cve/CVE-2019-13627.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4482.html">https://linux.oracle.com/errata/ELSA-2020-4482.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/09/msg00024.html">https://lists.debian.org/debian-lts-announce/2019/09/msg00024.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/01/msg00001.html">https://lists.debian.org/debian-lts-announce/2020/01/msg00001.html</a>
          <a href="https://minerva.crocs.fi.muni.cz/">https://minerva.crocs.fi.muni.cz/</a>
          <a href="https://security-tracker.debian.org/tracker/CVE-2019-13627">https://security-tracker.debian.org/tracker/CVE-2019-13627</a>
          <a href="https://security.gentoo.org/glsa/202003-32">https://security.gentoo.org/glsa/202003-32</a>
          <a href="https://ubuntu.com/security/notices/USN-4236-1">https://ubuntu.com/security/notices/USN-4236-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4236-2">https://ubuntu.com/security/notices/USN-4236-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4236-3">https://ubuntu.com/security/notices/USN-4236-3</a>
          <a href="https://usn.ubuntu.com/4236-1/">https://usn.ubuntu.com/4236-1/</a>
          <a href="https://usn.ubuntu.com/4236-2/">https://usn.ubuntu.com/4236-2/</a>
          <a href="https://usn.ubuntu.com/4236-3/">https://usn.ubuntu.com/4236-3/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2021-40528</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.7.6-2+deb9u3</td>
        <td>1.7.6-2+deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-40528">https://access.redhat.com/security/cve/CVE-2021-40528</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40528">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40528</a>
          <a href="https://dev.gnupg.org/rCb118681ebc4c9ea4b9da79b0f9541405a64f4c13">https://dev.gnupg.org/rCb118681ebc4c9ea4b9da79b0f9541405a64f4c13</a>
          <a href="https://eprint.iacr.org/2021/923">https://eprint.iacr.org/2021/923</a>
          <a href="https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=commit;h=3462280f2e23e16adf3ed5176e0f2413d8861320">https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=commit;h=3462280f2e23e16adf3ed5176e0f2413d8861320</a>
          <a href="https://ibm.github.io/system-security-research-updates/2021/07/20/insecurity-elgamal-pt1">https://ibm.github.io/system-security-research-updates/2021/07/20/insecurity-elgamal-pt1</a>
          <a href="https://ibm.github.io/system-security-research-updates/2021/09/06/insecurity-elgamal-pt2">https://ibm.github.io/system-security-research-updates/2021/09/06/insecurity-elgamal-pt2</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-40528">https://nvd.nist.gov/vuln/detail/CVE-2021-40528</a>
          <a href="https://ubuntu.com/security/notices/USN-5080-1">https://ubuntu.com/security/notices/USN-5080-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5080-2">https://ubuntu.com/security/notices/USN-5080-2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgmp10</td>
        <td>CVE-2021-43618</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2:6.1.2+dfsg-1</td>
        <td>2:6.1.2+dfsg-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-43618">https://access.redhat.com/security/cve/CVE-2021-43618</a>
          <a href="https://bugs.debian.org/994405">https://bugs.debian.org/994405</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618</a>
          <a href="https://gmplib.org/list-archives/gmp-bugs/2021-September/005077.html">https://gmplib.org/list-archives/gmp-bugs/2021-September/005077.html</a>
          <a href="https://gmplib.org/repo/gmp-6.2/rev/561a9c25298e">https://gmplib.org/repo/gmp-6.2/rev/561a9c25298e</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00001.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00001.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-43618">https://nvd.nist.gov/vuln/detail/CVE-2021-43618</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgnutls30</td>
        <td>CVE-2019-3829</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.5.8-5+deb9u4</td>
        <td>3.5.8-5+deb9u5</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00017.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00017.html</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3600">https://access.redhat.com/errata/RHSA-2019:3600</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-3829">https://access.redhat.com/security/cve/CVE-2019-3829</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3829">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3829</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3829">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3829</a>
          <a href="https://gitlab.com/gnutls/gnutls/issues/694">https://gitlab.com/gnutls/gnutls/issues/694</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3829.html">https://linux.oracle.com/cve/CVE-2019-3829.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3600.html">https://linux.oracle.com/errata/ELSA-2019-3600.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/A3ETBUFBB4G7AITAOUYPGXVMBGVXKUAN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/A3ETBUFBB4G7AITAOUYPGXVMBGVXKUAN/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7TJIBRJWGWSH6XIO2MXIQ3W6ES4R6I4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7TJIBRJWGWSH6XIO2MXIQ3W6ES4R6I4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WRSOL66LHP4SD3Y2ECJDOGT4K663ECDU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WRSOL66LHP4SD3Y2ECJDOGT4K663ECDU/</a>
          <a href="https://lists.gnupg.org/pipermail/gnutls-help/2019-March/004497.html">https://lists.gnupg.org/pipermail/gnutls-help/2019-March/004497.html</a>
          <a href="https://security.gentoo.org/glsa/201904-14">https://security.gentoo.org/glsa/201904-14</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0004/">https://security.netapp.com/advisory/ntap-20190619-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-3999-1">https://ubuntu.com/security/notices/USN-3999-1</a>
          <a href="https://usn.ubuntu.com/3999-1/">https://usn.ubuntu.com/3999-1/</a>
          <a href="https://www.gnutls.org/security-new.html#GNUTLS-SA-2019-03-27">https://www.gnutls.org/security-new.html#GNUTLS-SA-2019-03-27</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgnutls30</td>
        <td>CVE-2018-16868</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.5.8-5+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://cat.eyalro.net/">http://cat.eyalro.net/</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00017.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00017.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00068.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00068.html</a>
          <a href="http://www.securityfocus.com/bid/106080">http://www.securityfocus.com/bid/106080</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-16868">https://access.redhat.com/security/cve/CVE-2018-16868</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16868">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16868</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16868">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16868</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2020-28196</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-28196">https://access.redhat.com/security/cve/CVE-2020-28196</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196</a>
          <a href="https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd">https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-28196.html">https://linux.oracle.com/cve/CVE-2020-28196.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9294.html">https://linux.oracle.com/errata/ELSA-2021-9294.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-28196">https://nvd.nist.gov/vuln/detail/CVE-2020-28196</a>
          <a href="https://security.gentoo.org/glsa/202011-17">https://security.gentoo.org/glsa/202011-17</a>
          <a href="https://security.netapp.com/advisory/ntap-20201202-0001/">https://security.netapp.com/advisory/ntap-20201202-0001/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4635-1">https://ubuntu.com/security/notices/USN-4635-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4795">https://www.debian.org/security/2020/dsa-4795</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763">http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20217">https://access.redhat.com/security/cve/CVE-2018-20217</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217</a>
          <a href="https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086">https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0006/">https://security.netapp.com/advisory/ntap-20190416-0006/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2018-5710</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-5710">https://access.redhat.com/security/cve/CVE-2018-5710</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710</a>
          <a href="https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)">https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2018-5729</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.securitytracker.com/id/1042071">http://www.securitytracker.com/id/1042071</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3071">https://access.redhat.com/errata/RHSA-2018:3071</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-5729">https://access.redhat.com/security/cve/CVE-2018-5729</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1551083">https://bugzilla.redhat.com/show_bug.cgi?id=1551083</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729</a>
          <a href="https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1">https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-5729.html">https://linux.oracle.com/cve/CVE-2018-5729.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3071.html">https://linux.oracle.com/errata/ELSA-2018-3071.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-37750">https://access.redhat.com/security/cve/CVE-2021-37750</a>
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37750">https://nvd.nist.gov/vuln/detail/CVE-2021-37750</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libhogweed4</td>
        <td>CVE-2021-20305</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.3-1</td>
        <td>3.3-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20305">https://access.redhat.com/security/cve/CVE-2021-20305</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1942533">https://bugzilla.redhat.com/show_bug.cgi?id=1942533</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20305">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20305</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-20305.html">https://linux.oracle.com/cve/CVE-2021-20305.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1206.html">https://linux.oracle.com/errata/ELSA-2021-1206.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQKWVVMAIDAJ7YAA3VVO32BHLDOH2E63/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQKWVVMAIDAJ7YAA3VVO32BHLDOH2E63/</a>
          <a href="https://lists.lysator.liu.se/pipermail/nettle-bugs/2021/009457.html">https://lists.lysator.liu.se/pipermail/nettle-bugs/2021/009457.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-20305">https://nvd.nist.gov/vuln/detail/CVE-2021-20305</a>
          <a href="https://security.gentoo.org/glsa/202105-31">https://security.gentoo.org/glsa/202105-31</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0002/">https://security.netapp.com/advisory/ntap-20211022-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4906-1">https://ubuntu.com/security/notices/USN-4906-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4933">https://www.debian.org/security/2021/dsa-4933</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libhogweed4</td>
        <td>CVE-2021-3580</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.3-1</td>
        <td>3.3-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3580">https://access.redhat.com/security/cve/CVE-2021-3580</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1967983">https://bugzilla.redhat.com/show_bug.cgi?id=1967983</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3580">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3580</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3580.html">https://linux.oracle.com/cve/CVE-2021-3580.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4451.html">https://linux.oracle.com/errata/ELSA-2021-4451.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3580">https://nvd.nist.gov/vuln/detail/CVE-2021-3580</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0006/">https://security.netapp.com/advisory/ntap-20211104-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-4990-1">https://ubuntu.com/security/notices/USN-4990-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libhogweed4</td>
        <td>CVE-2018-16869</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.3-1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://cat.eyalro.net/">http://cat.eyalro.net/</a>
          <a href="http://www.securityfocus.com/bid/106092">http://www.securityfocus.com/bid/106092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-16869">https://access.redhat.com/security/cve/CVE-2018-16869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16869">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16869</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16869">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16869</a>
          <a href="https://lists.debian.org/debian-lts/2019/03/msg00021.html">https://lists.debian.org/debian-lts/2019/03/msg00021.html</a>
          <a href="https://lists.lysator.liu.se/pipermail/nettle-bugs/2018/007363.html">https://lists.lysator.liu.se/pipermail/nettle-bugs/2018/007363.html</a>
          <a href="https://ubuntu.com/security/notices/USN-4990-1">https://ubuntu.com/security/notices/USN-4990-1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libidn11</td>
        <td>CVE-2017-14062</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.33-1</td>
        <td>1.33-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://www.debian.org/security/2017/dsa-3988">http://www.debian.org/security/2017/dsa-3988</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-14062">https://access.redhat.com/security/cve/CVE-2017-14062</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14062">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14062</a>
          <a href="https://gitlab.com/libidn/libidn2/blob/master/NEWS">https://gitlab.com/libidn/libidn2/blob/master/NEWS</a>
          <a href="https://gitlab.com/libidn/libidn2/commit/3284eb342cd0ed1a18786e3fcdf0cdd7e76676bd">https://gitlab.com/libidn/libidn2/commit/3284eb342cd0ed1a18786e3fcdf0cdd7e76676bd</a>
          <a href="https://lists.debian.org/debian-lts-announce/2018/07/msg00040.html">https://lists.debian.org/debian-lts-announce/2018/07/msg00040.html</a>
          <a href="https://ubuntu.com/security/notices/USN-3421-1">https://ubuntu.com/security/notices/USN-3421-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3434-1">https://ubuntu.com/security/notices/USN-3434-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3434-2">https://ubuntu.com/security/notices/USN-3434-2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2020-28196</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-28196">https://access.redhat.com/security/cve/CVE-2020-28196</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196</a>
          <a href="https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd">https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-28196.html">https://linux.oracle.com/cve/CVE-2020-28196.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9294.html">https://linux.oracle.com/errata/ELSA-2021-9294.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-28196">https://nvd.nist.gov/vuln/detail/CVE-2020-28196</a>
          <a href="https://security.gentoo.org/glsa/202011-17">https://security.gentoo.org/glsa/202011-17</a>
          <a href="https://security.netapp.com/advisory/ntap-20201202-0001/">https://security.netapp.com/advisory/ntap-20201202-0001/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4635-1">https://ubuntu.com/security/notices/USN-4635-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4795">https://www.debian.org/security/2020/dsa-4795</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763">http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20217">https://access.redhat.com/security/cve/CVE-2018-20217</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217</a>
          <a href="https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086">https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0006/">https://security.netapp.com/advisory/ntap-20190416-0006/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2018-5710</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-5710">https://access.redhat.com/security/cve/CVE-2018-5710</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710</a>
          <a href="https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)">https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2018-5729</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.securitytracker.com/id/1042071">http://www.securitytracker.com/id/1042071</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3071">https://access.redhat.com/errata/RHSA-2018:3071</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-5729">https://access.redhat.com/security/cve/CVE-2018-5729</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1551083">https://bugzilla.redhat.com/show_bug.cgi?id=1551083</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729</a>
          <a href="https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1">https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-5729.html">https://linux.oracle.com/cve/CVE-2018-5729.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3071.html">https://linux.oracle.com/errata/ELSA-2018-3071.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-37750">https://access.redhat.com/security/cve/CVE-2021-37750</a>
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37750">https://nvd.nist.gov/vuln/detail/CVE-2021-37750</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2020-28196</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-28196">https://access.redhat.com/security/cve/CVE-2020-28196</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196</a>
          <a href="https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd">https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-28196.html">https://linux.oracle.com/cve/CVE-2020-28196.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9294.html">https://linux.oracle.com/errata/ELSA-2021-9294.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-28196">https://nvd.nist.gov/vuln/detail/CVE-2020-28196</a>
          <a href="https://security.gentoo.org/glsa/202011-17">https://security.gentoo.org/glsa/202011-17</a>
          <a href="https://security.netapp.com/advisory/ntap-20201202-0001/">https://security.netapp.com/advisory/ntap-20201202-0001/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4635-1">https://ubuntu.com/security/notices/USN-4635-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4795">https://www.debian.org/security/2020/dsa-4795</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763">http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20217">https://access.redhat.com/security/cve/CVE-2018-20217</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217</a>
          <a href="https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086">https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0006/">https://security.netapp.com/advisory/ntap-20190416-0006/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2018-5710</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-5710">https://access.redhat.com/security/cve/CVE-2018-5710</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710</a>
          <a href="https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)">https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2018-5729</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.securitytracker.com/id/1042071">http://www.securitytracker.com/id/1042071</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3071">https://access.redhat.com/errata/RHSA-2018:3071</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-5729">https://access.redhat.com/security/cve/CVE-2018-5729</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1551083">https://bugzilla.redhat.com/show_bug.cgi?id=1551083</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729</a>
          <a href="https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1">https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-5729.html">https://linux.oracle.com/cve/CVE-2018-5729.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3071.html">https://linux.oracle.com/errata/ELSA-2018-3071.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-37750">https://access.redhat.com/security/cve/CVE-2021-37750</a>
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37750">https://nvd.nist.gov/vuln/detail/CVE-2021-37750</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2020-28196</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-28196">https://access.redhat.com/security/cve/CVE-2020-28196</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28196</a>
          <a href="https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd">https://github.com/krb5/krb5/commit/57415dda6cf04e73ffc3723be518eddfae599bfd</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-28196.html">https://linux.oracle.com/cve/CVE-2020-28196.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9294.html">https://linux.oracle.com/errata/ELSA-2021-9294.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/45KKOZQWIIIW5C45PJVGQ32AXBSYNBE7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/73IGOG6CZAVMVNS4GGRMOLOZ7B6QVA7F/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KPH2V3WSQTELROZK3GFCPQDOFLKIZ6H5/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-28196">https://nvd.nist.gov/vuln/detail/CVE-2020-28196</a>
          <a href="https://security.gentoo.org/glsa/202011-17">https://security.gentoo.org/glsa/202011-17</a>
          <a href="https://security.netapp.com/advisory/ntap-20201202-0001/">https://security.netapp.com/advisory/ntap-20201202-0001/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4635-1">https://ubuntu.com/security/notices/USN-4635-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4795">https://www.debian.org/security/2020/dsa-4795</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763">http://krbdev.mit.edu/rt/Ticket/Display.html?id=8763</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20217">https://access.redhat.com/security/cve/CVE-2018-20217</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20217</a>
          <a href="https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086">https://github.com/krb5/krb5/commit/5e6d1796106df8ba6bc1973ee0917c170d929086</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KNHELH4YHNT6H2ESJWX2UIDXLBNGB2O/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0006/">https://security.netapp.com/advisory/ntap-20190416-0006/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2018-5710</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-5710">https://access.redhat.com/security/cve/CVE-2018-5710</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5710</a>
          <a href="https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)">https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service(DoS)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2018-5729</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.securitytracker.com/id/1042071">http://www.securitytracker.com/id/1042071</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3071">https://access.redhat.com/errata/RHSA-2018:3071</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-5729">https://access.redhat.com/security/cve/CVE-2018-5729</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1551083">https://bugzilla.redhat.com/show_bug.cgi?id=1551083</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5729</a>
          <a href="https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1">https://github.com/krb5/krb5/commit/e1caf6fb74981da62039846931ebdffed71309d1</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-5729.html">https://linux.oracle.com/cve/CVE-2018-5729.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3071.html">https://linux.oracle.com/errata/ELSA-2018-3071.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GK5T6JPMBHBPKS7HNGHYUUF4KKRMNSNU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OIFUL3CPM4S5TOXTTOCQ3CUZN6XCXUTR/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.15-1+deb9u1</td>
        <td>1.15-1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-37750">https://access.redhat.com/security/cve/CVE-2021-37750</a>
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37750">https://nvd.nist.gov/vuln/detail/CVE-2021-37750</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-12243</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00016.html">http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00016.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-12243">https://access.redhat.com/security/cve/CVE-2020-12243</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9202">https://bugs.openldap.org/show_bug.cgi?id=9202</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12243">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12243</a>
          <a href="https://git.openldap.org/openldap/openldap/-/blob/OPENLDAP_REL_ENG_2_4/CHANGES">https://git.openldap.org/openldap/openldap/-/blob/OPENLDAP_REL_ENG_2_4/CHANGES</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/98464c11df8247d6a11b52e294ba5dd4f0380440">https://git.openldap.org/openldap/openldap/-/commit/98464c11df8247d6a11b52e294ba5dd4f0380440</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-12243.html">https://linux.oracle.com/cve/CVE-2020-12243.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4041.html">https://linux.oracle.com/errata/ELSA-2020-4041.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/05/msg00001.html">https://lists.debian.org/debian-lts-announce/2020/05/msg00001.html</a>
          <a href="https://lists.openldap.org/hyperkitty/list/openldap-announce@openldap.org/thread/FUOYA6YCHBXMLANBJMSO22JD2NB22WGC/">https://lists.openldap.org/hyperkitty/list/openldap-announce@openldap.org/thread/FUOYA6YCHBXMLANBJMSO22JD2NB22WGC/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0003/">https://security.netapp.com/advisory/ntap-20200511-0003/</a>
          <a href="https://support.apple.com/kb/HT211289">https://support.apple.com/kb/HT211289</a>
          <a href="https://ubuntu.com/security/notices/USN-4352-1">https://ubuntu.com/security/notices/USN-4352-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4352-2">https://ubuntu.com/security/notices/USN-4352-2</a>
          <a href="https://usn.ubuntu.com/4352-1/">https://usn.ubuntu.com/4352-1/</a>
          <a href="https://usn.ubuntu.com/4352-2/">https://usn.ubuntu.com/4352-2/</a>
          <a href="https://www.debian.org/security/2020/dsa-4666">https://www.debian.org/security/2020/dsa-4666</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-25692</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u5</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25692">https://access.redhat.com/security/cve/CVE-2020-25692</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1894567">https://bugzilla.redhat.com/show_bug.cgi?id=1894567</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25692">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25692</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-25692.html">https://linux.oracle.com/cve/CVE-2020-25692.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1389.html">https://linux.oracle.com/errata/ELSA-2021-1389.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-25692">https://nvd.nist.gov/vuln/detail/CVE-2020-25692</a>
          <a href="https://security.netapp.com/advisory/ntap-20210108-0006/">https://security.netapp.com/advisory/ntap-20210108-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-4622-1">https://ubuntu.com/security/notices/USN-4622-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4622-2">https://ubuntu.com/security/notices/USN-4622-2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-25709</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u6</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Feb/14">http://seclists.org/fulldisclosure/2021/Feb/14</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-25709">https://access.redhat.com/security/cve/CVE-2020-25709</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1899675">https://bugzilla.redhat.com/show_bug.cgi?id=1899675</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25709">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25709</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c">https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210716-0003/">https://security.netapp.com/advisory/ntap-20210716-0003/</a>
          <a href="https://support.apple.com/kb/HT212147">https://support.apple.com/kb/HT212147</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-1">https://ubuntu.com/security/notices/USN-4634-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-2">https://ubuntu.com/security/notices/USN-4634-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4792">https://www.debian.org/security/2020/dsa-4792</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-25710</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25710">https://access.redhat.com/security/cve/CVE-2020-25710</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1899678">https://bugzilla.redhat.com/show_bug.cgi?id=1899678</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25710</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c">https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210716-0003/">https://security.netapp.com/advisory/ntap-20210716-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-1">https://ubuntu.com/security/notices/USN-4634-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-2">https://ubuntu.com/security/notices/USN-4634-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4792">https://www.debian.org/security/2020/dsa-4792</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36221</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36221">https://access.redhat.com/security/cve/CVE-2020-36221</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9404">https://bugs.openldap.org/show_bug.cgi?id=9404</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9424">https://bugs.openldap.org/show_bug.cgi?id=9424</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36221">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36221</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/38ac838e4150c626bbfa0082b7e2cf3a2bb4df31">https://git.openldap.org/openldap/openldap/-/commit/38ac838e4150c626bbfa0082b7e2cf3a2bb4df31</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/58c1748e81c843c5b6e61648d2a4d1d82b47e842">https://git.openldap.org/openldap/openldap/-/commit/58c1748e81c843c5b6e61648d2a4d1d82b47e842</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36221">https://nvd.nist.gov/vuln/detail/CVE-2020-36221</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36222">https://access.redhat.com/security/cve/CVE-2020-36222</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9406">https://bugs.openldap.org/show_bug.cgi?id=9406</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9407">https://bugs.openldap.org/show_bug.cgi?id=9407</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36222</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/02dfc32d658fadc25e4040f78e36592f6e1e1ca0">https://git.openldap.org/openldap/openldap/-/commit/02dfc32d658fadc25e4040f78e36592f6e1e1ca0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed">https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed.aa">https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed.aa</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36222">https://nvd.nist.gov/vuln/detail/CVE-2020-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36223</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36223">https://access.redhat.com/security/cve/CVE-2020-36223</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9408">https://bugs.openldap.org/show_bug.cgi?id=9408</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36223">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36223</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/21981053a1195ae1555e23df4d9ac68d34ede9dd">https://git.openldap.org/openldap/openldap/-/commit/21981053a1195ae1555e23df4d9ac68d34ede9dd</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36223">https://nvd.nist.gov/vuln/detail/CVE-2020-36223</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36224</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36224">https://access.redhat.com/security/cve/CVE-2020-36224</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9409">https://bugs.openldap.org/show_bug.cgi?id=9409</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36224">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36224</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36224">https://nvd.nist.gov/vuln/detail/CVE-2020-36224</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36225</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36225">https://access.redhat.com/security/cve/CVE-2020-36225</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9412">https://bugs.openldap.org/show_bug.cgi?id=9412</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36225">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36225</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36225">https://nvd.nist.gov/vuln/detail/CVE-2020-36225</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36226</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36226">https://access.redhat.com/security/cve/CVE-2020-36226</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9413">https://bugs.openldap.org/show_bug.cgi?id=9413</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36226">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36226</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E">https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36226">https://nvd.nist.gov/vuln/detail/CVE-2020-36226</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36227</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36227">https://access.redhat.com/security/cve/CVE-2020-36227</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9428">https://bugs.openldap.org/show_bug.cgi?id=9428</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36227">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36227</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/9d0e8485f3113505743baabf1167e01e4558ccf5">https://git.openldap.org/openldap/openldap/-/commit/9d0e8485f3113505743baabf1167e01e4558ccf5</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36227">https://nvd.nist.gov/vuln/detail/CVE-2020-36227</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36228</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36228">https://access.redhat.com/security/cve/CVE-2020-36228</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9427">https://bugs.openldap.org/show_bug.cgi?id=9427</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36228">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36228</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/91dccd25c347733b365adc74cb07d074512ed5ad">https://git.openldap.org/openldap/openldap/-/commit/91dccd25c347733b365adc74cb07d074512ed5ad</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36228">https://nvd.nist.gov/vuln/detail/CVE-2020-36228</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36229</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36229">https://access.redhat.com/security/cve/CVE-2020-36229</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9425">https://bugs.openldap.org/show_bug.cgi?id=9425</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36229">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36229</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/4bdfffd2889c0c5cdf58bebafbdc8fce4bb2bff0">https://git.openldap.org/openldap/openldap/-/commit/4bdfffd2889c0c5cdf58bebafbdc8fce4bb2bff0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36229">https://nvd.nist.gov/vuln/detail/CVE-2020-36229</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2020-36230</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36230">https://access.redhat.com/security/cve/CVE-2020-36230</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9423">https://bugs.openldap.org/show_bug.cgi?id=9423</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36230">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36230</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/8c1d96ee36ed98b32cd0e28b7069c7b8ea09d793">https://git.openldap.org/openldap/openldap/-/commit/8c1d96ee36ed98b32cd0e28b7069c7b8ea09d793</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36230">https://nvd.nist.gov/vuln/detail/CVE-2020-36230</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-2.4-2</td>
        <td>CVE-2021-27212</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u8</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-27212">https://access.redhat.com/security/cve/CVE-2021-27212</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9454">https://bugs.openldap.org/show_bug.cgi?id=9454</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27212">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27212</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/3539fc33212b528c56b716584f2c2994af7c30b0">https://git.openldap.org/openldap/openldap/-/commit/3539fc33212b528c56b716584f2c2994af7c30b0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/9badb73425a67768c09bcaed1a9c26c684af6c30">https://git.openldap.org/openldap/openldap/-/commit/9badb73425a67768c09bcaed1a9c26c684af6c30</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00035.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00035.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-27212">https://nvd.nist.gov/vuln/detail/CVE-2021-27212</a>
          <a href="https://security.netapp.com/advisory/ntap-20210319-0005/">https://security.netapp.com/advisory/ntap-20210319-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-4744-1">https://ubuntu.com/security/notices/USN-4744-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4860">https://www.debian.org/security/2021/dsa-4860</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-12243</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00016.html">http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00016.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-12243">https://access.redhat.com/security/cve/CVE-2020-12243</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9202">https://bugs.openldap.org/show_bug.cgi?id=9202</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12243">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12243</a>
          <a href="https://git.openldap.org/openldap/openldap/-/blob/OPENLDAP_REL_ENG_2_4/CHANGES">https://git.openldap.org/openldap/openldap/-/blob/OPENLDAP_REL_ENG_2_4/CHANGES</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/98464c11df8247d6a11b52e294ba5dd4f0380440">https://git.openldap.org/openldap/openldap/-/commit/98464c11df8247d6a11b52e294ba5dd4f0380440</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-12243.html">https://linux.oracle.com/cve/CVE-2020-12243.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4041.html">https://linux.oracle.com/errata/ELSA-2020-4041.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/05/msg00001.html">https://lists.debian.org/debian-lts-announce/2020/05/msg00001.html</a>
          <a href="https://lists.openldap.org/hyperkitty/list/openldap-announce@openldap.org/thread/FUOYA6YCHBXMLANBJMSO22JD2NB22WGC/">https://lists.openldap.org/hyperkitty/list/openldap-announce@openldap.org/thread/FUOYA6YCHBXMLANBJMSO22JD2NB22WGC/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0003/">https://security.netapp.com/advisory/ntap-20200511-0003/</a>
          <a href="https://support.apple.com/kb/HT211289">https://support.apple.com/kb/HT211289</a>
          <a href="https://ubuntu.com/security/notices/USN-4352-1">https://ubuntu.com/security/notices/USN-4352-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4352-2">https://ubuntu.com/security/notices/USN-4352-2</a>
          <a href="https://usn.ubuntu.com/4352-1/">https://usn.ubuntu.com/4352-1/</a>
          <a href="https://usn.ubuntu.com/4352-2/">https://usn.ubuntu.com/4352-2/</a>
          <a href="https://www.debian.org/security/2020/dsa-4666">https://www.debian.org/security/2020/dsa-4666</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-25692</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u5</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25692">https://access.redhat.com/security/cve/CVE-2020-25692</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1894567">https://bugzilla.redhat.com/show_bug.cgi?id=1894567</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25692">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25692</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-25692.html">https://linux.oracle.com/cve/CVE-2020-25692.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1389.html">https://linux.oracle.com/errata/ELSA-2021-1389.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-25692">https://nvd.nist.gov/vuln/detail/CVE-2020-25692</a>
          <a href="https://security.netapp.com/advisory/ntap-20210108-0006/">https://security.netapp.com/advisory/ntap-20210108-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-4622-1">https://ubuntu.com/security/notices/USN-4622-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4622-2">https://ubuntu.com/security/notices/USN-4622-2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-25709</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u6</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Feb/14">http://seclists.org/fulldisclosure/2021/Feb/14</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-25709">https://access.redhat.com/security/cve/CVE-2020-25709</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1899675">https://bugzilla.redhat.com/show_bug.cgi?id=1899675</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25709">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25709</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c">https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210716-0003/">https://security.netapp.com/advisory/ntap-20210716-0003/</a>
          <a href="https://support.apple.com/kb/HT212147">https://support.apple.com/kb/HT212147</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-1">https://ubuntu.com/security/notices/USN-4634-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-2">https://ubuntu.com/security/notices/USN-4634-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4792">https://www.debian.org/security/2020/dsa-4792</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-25710</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25710">https://access.redhat.com/security/cve/CVE-2020-25710</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1899678">https://bugzilla.redhat.com/show_bug.cgi?id=1899678</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25710">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25710</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c">https://git.openldap.org/openldap/openldap/-/commit/ab3915154e69920d480205b4bf5ccb2b391a0a1f#a2feb6ed0257c21c6672793ee2f94eaadc10c72c</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210716-0003/">https://security.netapp.com/advisory/ntap-20210716-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-1">https://ubuntu.com/security/notices/USN-4634-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4634-2">https://ubuntu.com/security/notices/USN-4634-2</a>
          <a href="https://www.debian.org/security/2020/dsa-4792">https://www.debian.org/security/2020/dsa-4792</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36221</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36221">https://access.redhat.com/security/cve/CVE-2020-36221</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9404">https://bugs.openldap.org/show_bug.cgi?id=9404</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9424">https://bugs.openldap.org/show_bug.cgi?id=9424</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36221">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36221</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/38ac838e4150c626bbfa0082b7e2cf3a2bb4df31">https://git.openldap.org/openldap/openldap/-/commit/38ac838e4150c626bbfa0082b7e2cf3a2bb4df31</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/58c1748e81c843c5b6e61648d2a4d1d82b47e842">https://git.openldap.org/openldap/openldap/-/commit/58c1748e81c843c5b6e61648d2a4d1d82b47e842</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36221">https://nvd.nist.gov/vuln/detail/CVE-2020-36221</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36222">https://access.redhat.com/security/cve/CVE-2020-36222</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9406">https://bugs.openldap.org/show_bug.cgi?id=9406</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9407">https://bugs.openldap.org/show_bug.cgi?id=9407</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36222</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/02dfc32d658fadc25e4040f78e36592f6e1e1ca0">https://git.openldap.org/openldap/openldap/-/commit/02dfc32d658fadc25e4040f78e36592f6e1e1ca0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed">https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed.aa">https://git.openldap.org/openldap/openldap/-/commit/6ed057b5b728b50746c869bcc9c1f85d0bbbf6ed.aa</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36222">https://nvd.nist.gov/vuln/detail/CVE-2020-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36223</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36223">https://access.redhat.com/security/cve/CVE-2020-36223</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9408">https://bugs.openldap.org/show_bug.cgi?id=9408</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36223">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36223</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/21981053a1195ae1555e23df4d9ac68d34ede9dd">https://git.openldap.org/openldap/openldap/-/commit/21981053a1195ae1555e23df4d9ac68d34ede9dd</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36223">https://nvd.nist.gov/vuln/detail/CVE-2020-36223</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36224</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36224">https://access.redhat.com/security/cve/CVE-2020-36224</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9409">https://bugs.openldap.org/show_bug.cgi?id=9409</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36224">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36224</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36224">https://nvd.nist.gov/vuln/detail/CVE-2020-36224</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36225</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36225">https://access.redhat.com/security/cve/CVE-2020-36225</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9412">https://bugs.openldap.org/show_bug.cgi?id=9412</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36225">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36225</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36225">https://nvd.nist.gov/vuln/detail/CVE-2020-36225</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36226</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36226">https://access.redhat.com/security/cve/CVE-2020-36226</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9413">https://bugs.openldap.org/show_bug.cgi?id=9413</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36226">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36226</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65">https://git.openldap.org/openldap/openldap/-/commit/554dff1927176579d652f2fe60c90e9abbad4c65</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26">https://git.openldap.org/openldap/openldap/-/commit/5a2017d4e61a6ddc4dcb4415028e0d08eb6bca26</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439">https://git.openldap.org/openldap/openldap/-/commit/c0b61a9486508e5202aa2e0cfb68c9813731b439</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8">https://git.openldap.org/openldap/openldap/-/commit/d169e7958a3e0dc70f59c8374bf8a59833b7bdd8</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E">https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36226">https://nvd.nist.gov/vuln/detail/CVE-2020-36226</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36227</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36227">https://access.redhat.com/security/cve/CVE-2020-36227</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9428">https://bugs.openldap.org/show_bug.cgi?id=9428</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36227">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36227</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/9d0e8485f3113505743baabf1167e01e4558ccf5">https://git.openldap.org/openldap/openldap/-/commit/9d0e8485f3113505743baabf1167e01e4558ccf5</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36227">https://nvd.nist.gov/vuln/detail/CVE-2020-36227</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36228</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36228">https://access.redhat.com/security/cve/CVE-2020-36228</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9427">https://bugs.openldap.org/show_bug.cgi?id=9427</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36228">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36228</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/91dccd25c347733b365adc74cb07d074512ed5ad">https://git.openldap.org/openldap/openldap/-/commit/91dccd25c347733b365adc74cb07d074512ed5ad</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36228">https://nvd.nist.gov/vuln/detail/CVE-2020-36228</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36229</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36229">https://access.redhat.com/security/cve/CVE-2020-36229</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9425">https://bugs.openldap.org/show_bug.cgi?id=9425</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36229">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36229</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/4bdfffd2889c0c5cdf58bebafbdc8fce4bb2bff0">https://git.openldap.org/openldap/openldap/-/commit/4bdfffd2889c0c5cdf58bebafbdc8fce4bb2bff0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36229">https://nvd.nist.gov/vuln/detail/CVE-2020-36229</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2020-36230</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/64">http://seclists.org/fulldisclosure/2021/May/64</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/65">http://seclists.org/fulldisclosure/2021/May/65</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-36230">https://access.redhat.com/security/cve/CVE-2020-36230</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9423">https://bugs.openldap.org/show_bug.cgi?id=9423</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36230">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36230</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/8c1d96ee36ed98b32cd0e28b7069c7b8ea09d793">https://git.openldap.org/openldap/openldap/-/commit/8c1d96ee36ed98b32cd0e28b7069c7b8ea09d793</a>
          <a href="https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57">https://git.openldap.org/openldap/openldap/-/tags/OPENLDAP_REL_ENG_2_4_57</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00005.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-36230">https://nvd.nist.gov/vuln/detail/CVE-2020-36230</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0002/">https://security.netapp.com/advisory/ntap-20210226-0002/</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212530">https://support.apple.com/kb/HT212530</a>
          <a href="https://support.apple.com/kb/HT212531">https://support.apple.com/kb/HT212531</a>
          <a href="https://ubuntu.com/security/notices/USN-4724-1">https://ubuntu.com/security/notices/USN-4724-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4845">https://www.debian.org/security/2021/dsa-4845</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libldap-common</td>
        <td>CVE-2021-27212</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.4.44+dfsg-5+deb9u3</td>
        <td>2.4.44+dfsg-5+deb9u8</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-27212">https://access.redhat.com/security/cve/CVE-2021-27212</a>
          <a href="https://bugs.openldap.org/show_bug.cgi?id=9454">https://bugs.openldap.org/show_bug.cgi?id=9454</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27212">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27212</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/3539fc33212b528c56b716584f2c2994af7c30b0">https://git.openldap.org/openldap/openldap/-/commit/3539fc33212b528c56b716584f2c2994af7c30b0</a>
          <a href="https://git.openldap.org/openldap/openldap/-/commit/9badb73425a67768c09bcaed1a9c26c684af6c30">https://git.openldap.org/openldap/openldap/-/commit/9badb73425a67768c09bcaed1a9c26c684af6c30</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/02/msg00035.html">https://lists.debian.org/debian-lts-announce/2021/02/msg00035.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-27212">https://nvd.nist.gov/vuln/detail/CVE-2021-27212</a>
          <a href="https://security.netapp.com/advisory/ntap-20210319-0005/">https://security.netapp.com/advisory/ntap-20210319-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-4744-1">https://ubuntu.com/security/notices/USN-4744-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4860">https://www.debian.org/security/2021/dsa-4860</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">liblz4-1</td>
        <td>CVE-2021-3520</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">0.0~r131-2</td>
        <td>0.0~r131-2+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3520.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3520.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3520">https://access.redhat.com/security/cve/CVE-2021-3520</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1954559">https://bugzilla.redhat.com/show_bug.cgi?id=1954559</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3520">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3520</a>
          <a href="https://github.com/lz4/lz4/pull/972">https://github.com/lz4/lz4/pull/972</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3520.html">https://linux.oracle.com/cve/CVE-2021-3520.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-2575.html">https://linux.oracle.com/errata/ELSA-2021-2575.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0005/">https://security.netapp.com/advisory/ntap-20211104-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-4968-1">https://ubuntu.com/security/notices/USN-4968-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4968-2">https://ubuntu.com/security/notices/USN-4968-2</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libmount1</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libnettle6</td>
        <td>CVE-2021-20305</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.3-1</td>
        <td>3.3-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20305">https://access.redhat.com/security/cve/CVE-2021-20305</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1942533">https://bugzilla.redhat.com/show_bug.cgi?id=1942533</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20305">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20305</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-20305.html">https://linux.oracle.com/cve/CVE-2021-20305.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1206.html">https://linux.oracle.com/errata/ELSA-2021-1206.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQKWVVMAIDAJ7YAA3VVO32BHLDOH2E63/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MQKWVVMAIDAJ7YAA3VVO32BHLDOH2E63/</a>
          <a href="https://lists.lysator.liu.se/pipermail/nettle-bugs/2021/009457.html">https://lists.lysator.liu.se/pipermail/nettle-bugs/2021/009457.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-20305">https://nvd.nist.gov/vuln/detail/CVE-2021-20305</a>
          <a href="https://security.gentoo.org/glsa/202105-31">https://security.gentoo.org/glsa/202105-31</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0002/">https://security.netapp.com/advisory/ntap-20211022-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4906-1">https://ubuntu.com/security/notices/USN-4906-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4933">https://www.debian.org/security/2021/dsa-4933</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libnettle6</td>
        <td>CVE-2021-3580</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.3-1</td>
        <td>3.3-1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3580">https://access.redhat.com/security/cve/CVE-2021-3580</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1967983">https://bugzilla.redhat.com/show_bug.cgi?id=1967983</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3580">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3580</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3580.html">https://linux.oracle.com/cve/CVE-2021-3580.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4451.html">https://linux.oracle.com/errata/ELSA-2021-4451.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00008.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3580">https://nvd.nist.gov/vuln/detail/CVE-2021-3580</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0006/">https://security.netapp.com/advisory/ntap-20211104-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-4990-1">https://ubuntu.com/security/notices/USN-4990-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnettle6</td>
        <td>CVE-2018-16869</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.3-1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://cat.eyalro.net/">http://cat.eyalro.net/</a>
          <a href="http://www.securityfocus.com/bid/106092">http://www.securityfocus.com/bid/106092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-16869">https://access.redhat.com/security/cve/CVE-2018-16869</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16869">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16869</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16869">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16869</a>
          <a href="https://lists.debian.org/debian-lts/2019/03/msg00021.html">https://lists.debian.org/debian-lts/2019/03/msg00021.html</a>
          <a href="https://lists.lysator.liu.se/pipermail/nettle-bugs/2018/007363.html">https://lists.lysator.liu.se/pipermail/nettle-bugs/2018/007363.html</a>
          <a href="https://ubuntu.com/security/notices/USN-4990-1">https://ubuntu.com/security/notices/USN-4990-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libnghttp2-14</td>
        <td>CVE-2018-1000168</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.18.1-1+deb9u1</td>
        <td>1.18.1-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/103952">http://www.securityfocus.com/bid/103952</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:0366">https://access.redhat.com/errata/RHSA-2019:0366</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:0367">https://access.redhat.com/errata/RHSA-2019:0367</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000168">https://access.redhat.com/security/cve/CVE-2018-1000168</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000168">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000168</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html</a>
          <a href="https://nghttp2.org/blog/2018/04/12/nghttp2-v1-31-1/">https://nghttp2.org/blog/2018/04/12/nghttp2-v1-31-1/</a>
          <a href="https://nodejs.org/en/blog/vulnerability/june-2018-security-releases/">https://nodejs.org/en/blog/vulnerability/june-2018-security-releases/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-1000168">https://nvd.nist.gov/vuln/detail/CVE-2018-1000168</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libnghttp2-14</td>
        <td>CVE-2020-11080</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.18.1-1+deb9u1</td>
        <td>1.18.1-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-11080">https://access.redhat.com/security/cve/CVE-2020-11080</a>
          <a href="https://github.com/nghttp2/nghttp2/commit/336a98feb0d56b9ac54e12736b18785c27f75090">https://github.com/nghttp2/nghttp2/commit/336a98feb0d56b9ac54e12736b18785c27f75090</a>
          <a href="https://github.com/nghttp2/nghttp2/commit/f8da73bd042f810f34d19f9eae02b46d870af394">https://github.com/nghttp2/nghttp2/commit/f8da73bd042f810f34d19f9eae02b46d870af394</a>
          <a href="https://github.com/nghttp2/nghttp2/security/advisories/GHSA-q5wr-xfw9-q7xr">https://github.com/nghttp2/nghttp2/security/advisories/GHSA-q5wr-xfw9-q7xr</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-11080.html">https://linux.oracle.com/cve/CVE-2020-11080.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5765.html">https://linux.oracle.com/errata/ELSA-2020-5765.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4OOYAMJVLLCLXDTHW3V5UXNULZBBK4O6/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4OOYAMJVLLCLXDTHW3V5UXNULZBBK4O6/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AAC2AA36OTRHKSVM5OV7TTVB3CZIGEFL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AAC2AA36OTRHKSVM5OV7TTVB3CZIGEFL/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-11080">https://nvd.nist.gov/vuln/detail/CVE-2020-11080</a>
          <a href="https://www.debian.org/security/2020/dsa-4696">https://www.debian.org/security/2020/dsa-4696</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libp11-kit0</td>
        <td>CVE-2020-29361</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">0.23.3-2</td>
        <td>0.23.3-2+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-29361">https://access.redhat.com/security/cve/CVE-2020-29361</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29361</a>
          <a href="https://github.com/p11-glue/p11-kit/releases">https://github.com/p11-glue/p11-kit/releases</a>
          <a href="https://github.com/p11-glue/p11-kit/security/advisories/GHSA-q4r3-hm6m-mvc2">https://github.com/p11-glue/p11-kit/security/advisories/GHSA-q4r3-hm6m-mvc2</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-29361.html">https://linux.oracle.com/cve/CVE-2020-29361.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1609.html">https://linux.oracle.com/errata/ELSA-2021-1609.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/01/msg00002.html">https://lists.debian.org/debian-lts-announce/2021/01/msg00002.html</a>
          <a href="https://lists.freedesktop.org/archives/p11-glue/2020-December/000712.html">https://lists.freedesktop.org/archives/p11-glue/2020-December/000712.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-29361">https://nvd.nist.gov/vuln/detail/CVE-2020-29361</a>
          <a href="https://ubuntu.com/security/notices/USN-4677-1">https://ubuntu.com/security/notices/USN-4677-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4677-2">https://ubuntu.com/security/notices/USN-4677-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4822">https://www.debian.org/security/2021/dsa-4822</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libp11-kit0</td>
        <td>CVE-2020-29362</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">0.23.3-2</td>
        <td>0.23.3-2+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-29362">https://access.redhat.com/security/cve/CVE-2020-29362</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29362">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29362</a>
          <a href="https://github.com/p11-glue/p11-kit/releases">https://github.com/p11-glue/p11-kit/releases</a>
          <a href="https://github.com/p11-glue/p11-kit/security/advisories/GHSA-5wpq-43j2-6qwc">https://github.com/p11-glue/p11-kit/security/advisories/GHSA-5wpq-43j2-6qwc</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-29362.html">https://linux.oracle.com/cve/CVE-2020-29362.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1609.html">https://linux.oracle.com/errata/ELSA-2021-1609.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/01/msg00002.html">https://lists.debian.org/debian-lts-announce/2021/01/msg00002.html</a>
          <a href="https://lists.freedesktop.org/archives/p11-glue/2020-December/000712.html">https://lists.freedesktop.org/archives/p11-glue/2020-December/000712.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-29362">https://nvd.nist.gov/vuln/detail/CVE-2020-29362</a>
          <a href="https://ubuntu.com/security/notices/USN-4677-1">https://ubuntu.com/security/notices/USN-4677-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4822">https://www.debian.org/security/2021/dsa-4822</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpcre3</td>
        <td>CVE-2020-14155</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.39-3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Dec/32">http://seclists.org/fulldisclosure/2020/Dec/32</a>
          <a href="http://seclists.org/fulldisclosure/2021/Feb/14">http://seclists.org/fulldisclosure/2021/Feb/14</a>
          <a href="https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/">https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-14155">https://access.redhat.com/security/cve/CVE-2020-14155</a>
          <a href="https://bugs.gentoo.org/717920">https://bugs.gentoo.org/717920</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-14155.html">https://linux.oracle.com/cve/CVE-2020-14155.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4373.html">https://linux.oracle.com/errata/ELSA-2021-4373.html</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-14155">https://nvd.nist.gov/vuln/detail/CVE-2020-14155</a>
          <a href="https://support.apple.com/kb/HT211931">https://support.apple.com/kb/HT211931</a>
          <a href="https://support.apple.com/kb/HT212147">https://support.apple.com/kb/HT212147</a>
          <a href="https://www.pcre.org/original/changelog.txt">https://www.pcre.org/original/changelog.txt</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsasl2-2</td>
        <td>CVE-2019-19906</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.27~101-g0780600+dfsg-3</td>
        <td>2.1.27~101-g0780600+dfsg-3+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Jul/23">http://seclists.org/fulldisclosure/2020/Jul/23</a>
          <a href="http://seclists.org/fulldisclosure/2020/Jul/24">http://seclists.org/fulldisclosure/2020/Jul/24</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-19906">https://access.redhat.com/security/cve/CVE-2019-19906</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19906">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19906</a>
          <a href="https://github.com/cyrusimap/cyrus-sasl/issues/587">https://github.com/cyrusimap/cyrus-sasl/issues/587</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-19906.html">https://linux.oracle.com/cve/CVE-2019-19906.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4497.html">https://linux.oracle.com/errata/ELSA-2020-4497.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/12/msg00027.html">https://lists.debian.org/debian-lts-announce/2019/12/msg00027.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MW6GZCLECGL2PBNHVNPJIX4RPVRVFR7R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MW6GZCLECGL2PBNHVNPJIX4RPVRVFR7R/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OB4GSVOJ6ESHQNT5GSV63OX5D4KPSTGT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OB4GSVOJ6ESHQNT5GSV63OX5D4KPSTGT/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-19906">https://nvd.nist.gov/vuln/detail/CVE-2019-19906</a>
          <a href="https://seclists.org/bugtraq/2019/Dec/42">https://seclists.org/bugtraq/2019/Dec/42</a>
          <a href="https://support.apple.com/kb/HT211288">https://support.apple.com/kb/HT211288</a>
          <a href="https://support.apple.com/kb/HT211289">https://support.apple.com/kb/HT211289</a>
          <a href="https://ubuntu.com/security/notices/USN-4256-1">https://ubuntu.com/security/notices/USN-4256-1</a>
          <a href="https://usn.ubuntu.com/4256-1/">https://usn.ubuntu.com/4256-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4591">https://www.debian.org/security/2019/dsa-4591</a>
          <a href="https://www.openldap.org/its/index.cgi/Incoming?id=9123">https://www.openldap.org/its/index.cgi/Incoming?id=9123</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsasl2-modules-db</td>
        <td>CVE-2019-19906</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.1.27~101-g0780600+dfsg-3</td>
        <td>2.1.27~101-g0780600+dfsg-3+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Jul/23">http://seclists.org/fulldisclosure/2020/Jul/23</a>
          <a href="http://seclists.org/fulldisclosure/2020/Jul/24">http://seclists.org/fulldisclosure/2020/Jul/24</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-19906">https://access.redhat.com/security/cve/CVE-2019-19906</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19906">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19906</a>
          <a href="https://github.com/cyrusimap/cyrus-sasl/issues/587">https://github.com/cyrusimap/cyrus-sasl/issues/587</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-19906.html">https://linux.oracle.com/cve/CVE-2019-19906.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4497.html">https://linux.oracle.com/errata/ELSA-2020-4497.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/12/msg00027.html">https://lists.debian.org/debian-lts-announce/2019/12/msg00027.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MW6GZCLECGL2PBNHVNPJIX4RPVRVFR7R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MW6GZCLECGL2PBNHVNPJIX4RPVRVFR7R/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OB4GSVOJ6ESHQNT5GSV63OX5D4KPSTGT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OB4GSVOJ6ESHQNT5GSV63OX5D4KPSTGT/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-19906">https://nvd.nist.gov/vuln/detail/CVE-2019-19906</a>
          <a href="https://seclists.org/bugtraq/2019/Dec/42">https://seclists.org/bugtraq/2019/Dec/42</a>
          <a href="https://support.apple.com/kb/HT211288">https://support.apple.com/kb/HT211288</a>
          <a href="https://support.apple.com/kb/HT211289">https://support.apple.com/kb/HT211289</a>
          <a href="https://ubuntu.com/security/notices/USN-4256-1">https://ubuntu.com/security/notices/USN-4256-1</a>
          <a href="https://usn.ubuntu.com/4256-1/">https://usn.ubuntu.com/4256-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4591">https://www.debian.org/security/2019/dsa-4591</a>
          <a href="https://www.openldap.org/its/index.cgi/Incoming?id=9123">https://www.openldap.org/its/index.cgi/Incoming?id=9123</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsmartcols1</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-8457</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00074.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00074.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-8457">https://access.redhat.com/security/cve/CVE-2019-8457</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8457">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8457</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-8457.html">https://linux.oracle.com/cve/CVE-2019-8457.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1810.html">https://linux.oracle.com/errata/ELSA-2020-1810.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPKYSWCOM3CL66RI76TYVIG6TJ263RXH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPKYSWCOM3CL66RI76TYVIG6TJ263RXH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SJPFGA45DI4F5MCF2OAACGH3HQOF4G3M/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SJPFGA45DI4F5MCF2OAACGH3HQOF4G3M/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190606-0002/">https://security.netapp.com/advisory/ntap-20190606-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4004-1">https://ubuntu.com/security/notices/USN-4004-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4004-2">https://ubuntu.com/security/notices/USN-4004-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-1">https://ubuntu.com/security/notices/USN-4019-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-2">https://ubuntu.com/security/notices/USN-4019-2</a>
          <a href="https://usn.ubuntu.com/4004-1/">https://usn.ubuntu.com/4004-1/</a>
          <a href="https://usn.ubuntu.com/4004-2/">https://usn.ubuntu.com/4004-2/</a>
          <a href="https://usn.ubuntu.com/4019-1/">https://usn.ubuntu.com/4019-1/</a>
          <a href="https://usn.ubuntu.com/4019-2/">https://usn.ubuntu.com/4019-2/</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
          <a href="https://www.sqlite.org/releaselog/3_28_0.html">https://www.sqlite.org/releaselog/3_28_0.html</a>
          <a href="https://www.sqlite.org/src/info/90acdbfce9c08858">https://www.sqlite.org/src/info/90acdbfce9c08858</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2018-20346</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00040.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00070.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00070.html</a>
          <a href="http://www.securityfocus.com/bid/106323">http://www.securityfocus.com/bid/106323</a>
          <a href="https://access.redhat.com/articles/3758321">https://access.redhat.com/articles/3758321</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20346">https://access.redhat.com/security/cve/CVE-2018-20346</a>
          <a href="https://blade.tencent.com/magellan/index_en.html">https://blade.tencent.com/magellan/index_en.html</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1659379">https://bugzilla.redhat.com/show_bug.cgi?id=1659379</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1659677">https://bugzilla.redhat.com/show_bug.cgi?id=1659677</a>
          <a href="https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html">https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html</a>
          <a href="https://chromium.googlesource.com/chromium/src/+/c368e30ae55600a1c3c9cb1710a54f9c55de786e">https://chromium.googlesource.com/chromium/src/+/c368e30ae55600a1c3c9cb1710a54f9c55de786e</a>
          <a href="https://crbug.com/900910">https://crbug.com/900910</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20346">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20346</a>
          <a href="https://github.com/zhuowei/worthdoingbadly.com/blob/master/_posts/2018-12-14-sqlitebug.html">https://github.com/zhuowei/worthdoingbadly.com/blob/master/_posts/2018-12-14-sqlitebug.html</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365</a>
          <a href="https://lists.debian.org/debian-lts-announce/2018/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2018/12/msg00012.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PU4NZ6DDU4BEM3ACM3FM6GLEPX56ZQXK/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PU4NZ6DDU4BEM3ACM3FM6GLEPX56ZQXK/</a>
          <a href="https://news.ycombinator.com/item?id=18685296">https://news.ycombinator.com/item?id=18685296</a>
          <a href="https://security.gentoo.org/glsa/201904-21">https://security.gentoo.org/glsa/201904-21</a>
          <a href="https://sqlite.org/src/info/940f2adc8541a838">https://sqlite.org/src/info/940f2adc8541a838</a>
          <a href="https://sqlite.org/src/info/d44318f59044162e">https://sqlite.org/src/info/d44318f59044162e</a>
          <a href="https://support.apple.com/HT209443">https://support.apple.com/HT209443</a>
          <a href="https://support.apple.com/HT209446">https://support.apple.com/HT209446</a>
          <a href="https://support.apple.com/HT209447">https://support.apple.com/HT209447</a>
          <a href="https://support.apple.com/HT209448">https://support.apple.com/HT209448</a>
          <a href="https://support.apple.com/HT209450">https://support.apple.com/HT209450</a>
          <a href="https://support.apple.com/HT209451">https://support.apple.com/HT209451</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-1">https://ubuntu.com/security/notices/USN-4019-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-2">https://ubuntu.com/security/notices/USN-4019-2</a>
          <a href="https://usn.ubuntu.com/4019-1/">https://usn.ubuntu.com/4019-1/</a>
          <a href="https://usn.ubuntu.com/4019-2/">https://usn.ubuntu.com/4019-2/</a>
          <a href="https://worthdoingbadly.com/sqlitebug/">https://worthdoingbadly.com/sqlitebug/</a>
          <a href="https://www.freebsd.org/security/advisories/FreeBSD-EN-19:03.sqlite.asc">https://www.freebsd.org/security/advisories/FreeBSD-EN-19:03.sqlite.asc</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg113218.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg113218.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.sqlite.org/releaselog/3_25_3.html">https://www.sqlite.org/releaselog/3_25_3.html</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_18_61">https://www.synology.com/security/advisory/Synology_SA_18_61</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2018-20506</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00070.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00070.html</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/62">http://seclists.org/fulldisclosure/2019/Jan/62</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/64">http://seclists.org/fulldisclosure/2019/Jan/64</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/66">http://seclists.org/fulldisclosure/2019/Jan/66</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/67">http://seclists.org/fulldisclosure/2019/Jan/67</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/68">http://seclists.org/fulldisclosure/2019/Jan/68</a>
          <a href="http://seclists.org/fulldisclosure/2019/Jan/69">http://seclists.org/fulldisclosure/2019/Jan/69</a>
          <a href="http://www.securityfocus.com/bid/106698">http://www.securityfocus.com/bid/106698</a>
          <a href="https://access.redhat.com/articles/3758321">https://access.redhat.com/articles/3758321</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20506">https://access.redhat.com/security/cve/CVE-2018-20506</a>
          <a href="https://blade.tencent.com/magellan/index_en.html">https://blade.tencent.com/magellan/index_en.html</a>
          <a href="https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html">https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20506">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20506</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/28">https://seclists.org/bugtraq/2019/Jan/28</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/29">https://seclists.org/bugtraq/2019/Jan/29</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/31">https://seclists.org/bugtraq/2019/Jan/31</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/32">https://seclists.org/bugtraq/2019/Jan/32</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/33">https://seclists.org/bugtraq/2019/Jan/33</a>
          <a href="https://seclists.org/bugtraq/2019/Jan/39">https://seclists.org/bugtraq/2019/Jan/39</a>
          <a href="https://security.netapp.com/advisory/ntap-20190502-0004/">https://security.netapp.com/advisory/ntap-20190502-0004/</a>
          <a href="https://sqlite.org/src/info/940f2adc8541a838">https://sqlite.org/src/info/940f2adc8541a838</a>
          <a href="https://support.apple.com/kb/HT209443">https://support.apple.com/kb/HT209443</a>
          <a href="https://support.apple.com/kb/HT209446">https://support.apple.com/kb/HT209446</a>
          <a href="https://support.apple.com/kb/HT209447">https://support.apple.com/kb/HT209447</a>
          <a href="https://support.apple.com/kb/HT209448">https://support.apple.com/kb/HT209448</a>
          <a href="https://support.apple.com/kb/HT209450">https://support.apple.com/kb/HT209450</a>
          <a href="https://support.apple.com/kb/HT209451">https://support.apple.com/kb/HT209451</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-1">https://ubuntu.com/security/notices/USN-4019-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-2">https://ubuntu.com/security/notices/USN-4019-2</a>
          <a href="https://usn.ubuntu.com/4019-1/">https://usn.ubuntu.com/4019-1/</a>
          <a href="https://usn.ubuntu.com/4019-2/">https://usn.ubuntu.com/4019-2/</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2018-8740</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00050.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00050.html</a>
          <a href="http://www.securityfocus.com/bid/103466">http://www.securityfocus.com/bid/103466</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-8740">https://access.redhat.com/security/cve/CVE-2018-8740</a>
          <a href="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=6964">https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=6964</a>
          <a href="https://bugs.launchpad.net/ubuntu/+source/sqlite3/+bug/1756349">https://bugs.launchpad.net/ubuntu/+source/sqlite3/+bug/1756349</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8740">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8740</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/01/msg00009.html">https://lists.debian.org/debian-lts-announce/2019/01/msg00009.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PU4NZ6DDU4BEM3ACM3FM6GLEPX56ZQXK/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PU4NZ6DDU4BEM3ACM3FM6GLEPX56ZQXK/</a>
          <a href="https://ubuntu.com/security/notices/USN-4205-1">https://ubuntu.com/security/notices/USN-4205-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4394-1">https://ubuntu.com/security/notices/USN-4394-1</a>
          <a href="https://usn.ubuntu.com/4205-1/">https://usn.ubuntu.com/4205-1/</a>
          <a href="https://usn.ubuntu.com/4394-1/">https://usn.ubuntu.com/4394-1/</a>
          <a href="https://www.sqlite.org/cgi/src/timeline?r=corrupt-schema">https://www.sqlite.org/cgi/src/timeline?r=corrupt-schema</a>
          <a href="https://www.sqlite.org/cgi/src/vdiff?from=1774f1c3baf0bc3d&amp;to=d75e67654aa9620b">https://www.sqlite.org/cgi/src/vdiff?from=1774f1c3baf0bc3d&amp;to=d75e67654aa9620b</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-20218</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-20218">https://access.redhat.com/security/cve/CVE-2019-20218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20218</a>
          <a href="https://github.com/sqlite/sqlite/commit/a6c1a71cde082e09750465d5675699062922e387">https://github.com/sqlite/sqlite/commit/a6c1a71cde082e09750465d5675699062922e387</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-20218.html">https://linux.oracle.com/cve/CVE-2019-20218.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4442.html">https://linux.oracle.com/errata/ELSA-2020-4442.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00016.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00016.html</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://ubuntu.com/security/notices/USN-4298-1">https://ubuntu.com/security/notices/USN-4298-1</a>
          <a href="https://usn.ubuntu.com/4298-1/">https://usn.ubuntu.com/4298-1/</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-5827</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00085.html">http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00085.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-5827">https://access.redhat.com/security/cve/CVE-2019-5827</a>
          <a href="https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html">https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html</a>
          <a href="https://crbug.com/952406">https://crbug.com/952406</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5827">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5827</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-5827.html">https://linux.oracle.com/cve/CVE-2019-5827.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4396.html">https://linux.oracle.com/errata/ELSA-2021-4396.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CPM7VPE27DUNJLXM4F5PAAEFFWOEND6X/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CPM7VPE27DUNJLXM4F5PAAEFFWOEND6X/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FKN4GPMBQ3SDXWB4HL45II5CZ7P2E4AI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FKN4GPMBQ3SDXWB4HL45II5CZ7P2E4AI/</a>
          <a href="https://seclists.org/bugtraq/2019/Aug/19">https://seclists.org/bugtraq/2019/Aug/19</a>
          <a href="https://security.gentoo.org/glsa/202003-16">https://security.gentoo.org/glsa/202003-16</a>
          <a href="https://ubuntu.com/security/notices/USN-4205-1">https://ubuntu.com/security/notices/USN-4205-1</a>
          <a href="https://usn.ubuntu.com/4205-1/">https://usn.ubuntu.com/4205-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4500">https://www.debian.org/security/2019/dsa-4500</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-9936</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00026.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00026.html</a>
          <a href="http://www.securityfocus.com/bid/107562">http://www.securityfocus.com/bid/107562</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9936">https://access.redhat.com/security/cve/CVE-2019-9936</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9936">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9936</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXD2GYJVTDGEQPUNMMMC5TB7MQXOBBMO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXD2GYJVTDGEQPUNMMMC5TB7MQXOBBMO/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N66U5PY5UJU4XBFZJH7QNKIDNAVIB4OP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N66U5PY5UJU4XBFZJH7QNKIDNAVIB4OP/</a>
          <a href="https://security.gentoo.org/glsa/201908-09">https://security.gentoo.org/glsa/201908-09</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0005/">https://security.netapp.com/advisory/ntap-20190416-0005/</a>
          <a href="https://sqlite.org/src/info/b3fa58dd7403dbd4">https://sqlite.org/src/info/b3fa58dd7403dbd4</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-1">https://ubuntu.com/security/notices/USN-4019-1</a>
          <a href="https://usn.ubuntu.com/4019-1/">https://usn.ubuntu.com/4019-1/</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114382.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114382.html</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114394.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114394.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-9937</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00026.html">http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00026.html</a>
          <a href="http://www.securityfocus.com/bid/107562">http://www.securityfocus.com/bid/107562</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9937">https://access.redhat.com/security/cve/CVE-2019-9937</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9937">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9937</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXD2GYJVTDGEQPUNMMMC5TB7MQXOBBMO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXD2GYJVTDGEQPUNMMMC5TB7MQXOBBMO/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N66U5PY5UJU4XBFZJH7QNKIDNAVIB4OP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N66U5PY5UJU4XBFZJH7QNKIDNAVIB4OP/</a>
          <a href="https://security.gentoo.org/glsa/201908-09">https://security.gentoo.org/glsa/201908-09</a>
          <a href="https://security.netapp.com/advisory/ntap-20190416-0005/">https://security.netapp.com/advisory/ntap-20190416-0005/</a>
          <a href="https://sqlite.org/src/info/45c73deb440496e8">https://sqlite.org/src/info/45c73deb440496e8</a>
          <a href="https://ubuntu.com/security/notices/USN-4019-1">https://ubuntu.com/security/notices/USN-4019-1</a>
          <a href="https://usn.ubuntu.com/4019-1/">https://usn.ubuntu.com/4019-1/</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114383.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114383.html</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114393.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg114393.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-11655</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-11655">https://access.redhat.com/security/cve/CVE-2020-11655</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11655">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11655</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/05/msg00006.html">https://lists.debian.org/debian-lts-announce/2020/05/msg00006.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://security.netapp.com/advisory/ntap-20200416-0001/">https://security.netapp.com/advisory/ntap-20200416-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4394-1">https://ubuntu.com/security/notices/USN-4394-1</a>
          <a href="https://usn.ubuntu.com/4394-1/">https://usn.ubuntu.com/4394-1/</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www3.sqlite.org/cgi/src/info/4a302b42c7bf5e11">https://www3.sqlite.org/cgi/src/info/4a302b42c7bf5e11</a>
          <a href="https://www3.sqlite.org/cgi/src/tktview?name=af4556bb5c">https://www3.sqlite.org/cgi/src/tktview?name=af4556bb5c</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-13630</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Dec/32">http://seclists.org/fulldisclosure/2020/Dec/32</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/19">http://seclists.org/fulldisclosure/2020/Nov/19</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/20">http://seclists.org/fulldisclosure/2020/Nov/20</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/22">http://seclists.org/fulldisclosure/2020/Nov/22</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13630">https://access.redhat.com/security/cve/CVE-2020-13630</a>
          <a href="https://bugs.chromium.org/p/chromium/issues/detail?id=1080459">https://bugs.chromium.org/p/chromium/issues/detail?id=1080459</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13630">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13630</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-13630.html">https://linux.oracle.com/cve/CVE-2020-13630.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4442.html">https://linux.oracle.com/errata/ELSA-2020-4442.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://security.netapp.com/advisory/ntap-20200608-0002/">https://security.netapp.com/advisory/ntap-20200608-0002/</a>
          <a href="https://sqlite.org/src/info/0d69f76f0865f962">https://sqlite.org/src/info/0d69f76f0865f962</a>
          <a href="https://support.apple.com/kb/HT211843">https://support.apple.com/kb/HT211843</a>
          <a href="https://support.apple.com/kb/HT211844">https://support.apple.com/kb/HT211844</a>
          <a href="https://support.apple.com/kb/HT211850">https://support.apple.com/kb/HT211850</a>
          <a href="https://support.apple.com/kb/HT211931">https://support.apple.com/kb/HT211931</a>
          <a href="https://support.apple.com/kb/HT211935">https://support.apple.com/kb/HT211935</a>
          <a href="https://support.apple.com/kb/HT211952">https://support.apple.com/kb/HT211952</a>
          <a href="https://ubuntu.com/security/notices/USN-4394-1">https://ubuntu.com/security/notices/USN-4394-1</a>
          <a href="https://usn.ubuntu.com/4394-1/">https://usn.ubuntu.com/4394-1/</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-13871</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-13871">https://access.redhat.com/security/cve/CVE-2020-13871</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BN32AGQPMHZRNM6P6L5GZPETOWTGXOKP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BN32AGQPMHZRNM6P6L5GZPETOWTGXOKP/</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://security.netapp.com/advisory/ntap-20200619-0002/">https://security.netapp.com/advisory/ntap-20200619-0002/</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.sqlite.org/src/info/79eff1d0383179c4">https://www.sqlite.org/src/info/79eff1d0383179c4</a>
          <a href="https://www.sqlite.org/src/info/c8d3b9f0a750a529">https://www.sqlite.org/src/info/c8d3b9f0a750a529</a>
          <a href="https://www.sqlite.org/src/info/cd708fa84d2aaaea">https://www.sqlite.org/src/info/cd708fa84d2aaaea</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2019-16168</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00032.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00032.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-16168">https://access.redhat.com/security/cve/CVE-2019-16168</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16168">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16168</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10365</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-16168.html">https://linux.oracle.com/cve/CVE-2019-16168.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4442.html">https://linux.oracle.com/errata/ELSA-2020-4442.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XZARJHJJDBHI7CE5PZEBXS5HKK6HXKW2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XZARJHJJDBHI7CE5PZEBXS5HKK6HXKW2/</a>
          <a href="https://security.gentoo.org/glsa/202003-16">https://security.gentoo.org/glsa/202003-16</a>
          <a href="https://security.netapp.com/advisory/ntap-20190926-0003/">https://security.netapp.com/advisory/ntap-20190926-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200122-0003/">https://security.netapp.com/advisory/ntap-20200122-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-4205-1">https://ubuntu.com/security/notices/USN-4205-1</a>
          <a href="https://usn.ubuntu.com/4205-1/">https://usn.ubuntu.com/4205-1/</a>
          <a href="https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg116312.html">https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg116312.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuapr2020.html">https://www.oracle.com/security-alerts/cpuapr2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2020.html">https://www.oracle.com/security-alerts/cpujan2020.html</a>
          <a href="https://www.sqlite.org/src/info/e4598ecbdd18bd82945f6029013296690e719a62">https://www.sqlite.org/src/info/e4598ecbdd18bd82945f6029013296690e719a62</a>
          <a href="https://www.sqlite.org/src/timeline?c=98357d8c1263920b">https://www.sqlite.org/src/timeline?c=98357d8c1263920b</a>
          <a href="https://www.tenable.com/security/tns-2021-08">https://www.tenable.com/security/tns-2021-08</a>
          <a href="https://www.tenable.com/security/tns-2021-11">https://www.tenable.com/security/tns-2021-11</a>
          <a href="https://www.tenable.com/security/tns-2021-14">https://www.tenable.com/security/tns-2021-14</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-13434</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Dec/32">http://seclists.org/fulldisclosure/2020/Dec/32</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/19">http://seclists.org/fulldisclosure/2020/Nov/19</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/20">http://seclists.org/fulldisclosure/2020/Nov/20</a>
          <a href="http://seclists.org/fulldisclosure/2020/Nov/22">http://seclists.org/fulldisclosure/2020/Nov/22</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13434">https://access.redhat.com/security/cve/CVE-2020-13434</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13434">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13434</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-13434.html">https://linux.oracle.com/cve/CVE-2020-13434.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1581.html">https://linux.oracle.com/errata/ELSA-2021-1581.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/05/msg00024.html">https://lists.debian.org/debian-lts-announce/2020/05/msg00024.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://security.netapp.com/advisory/ntap-20200528-0004/">https://security.netapp.com/advisory/ntap-20200528-0004/</a>
          <a href="https://support.apple.com/kb/HT211843">https://support.apple.com/kb/HT211843</a>
          <a href="https://support.apple.com/kb/HT211844">https://support.apple.com/kb/HT211844</a>
          <a href="https://support.apple.com/kb/HT211850">https://support.apple.com/kb/HT211850</a>
          <a href="https://support.apple.com/kb/HT211931">https://support.apple.com/kb/HT211931</a>
          <a href="https://support.apple.com/kb/HT211935">https://support.apple.com/kb/HT211935</a>
          <a href="https://support.apple.com/kb/HT211952">https://support.apple.com/kb/HT211952</a>
          <a href="https://ubuntu.com/security/notices/USN-4394-1">https://ubuntu.com/security/notices/USN-4394-1</a>
          <a href="https://usn.ubuntu.com/4394-1/">https://usn.ubuntu.com/4394-1/</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.sqlite.org/src/info/23439ea582241138">https://www.sqlite.org/src/info/23439ea582241138</a>
          <a href="https://www.sqlite.org/src/info/d08d3405878d394e">https://www.sqlite.org/src/info/d08d3405878d394e</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-13632</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.16.2-5+deb9u1</td>
        <td>3.16.2-5+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-13632">https://access.redhat.com/security/cve/CVE-2020-13632</a>
          <a href="https://bugs.chromium.org/p/chromium/issues/detail?id=1080459">https://bugs.chromium.org/p/chromium/issues/detail?id=1080459</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13632">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13632</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-13632.html">https://linux.oracle.com/cve/CVE-2020-13632.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4442.html">https://linux.oracle.com/errata/ELSA-2020-4442.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html">https://lists.debian.org/debian-lts-announce/2020/08/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc</a>
          <a href="https://security.gentoo.org/glsa/202007-26">https://security.gentoo.org/glsa/202007-26</a>
          <a href="https://security.netapp.com/advisory/ntap-20200608-0002/">https://security.netapp.com/advisory/ntap-20200608-0002/</a>
          <a href="https://sqlite.org/src/info/a4dd148928ea65bd">https://sqlite.org/src/info/a4dd148928ea65bd</a>
          <a href="https://ubuntu.com/security/notices/USN-4394-1">https://ubuntu.com/security/notices/USN-4394-1</a>
          <a href="https://usn.ubuntu.com/4394-1/">https://usn.ubuntu.com/4394-1/</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssh2-1</td>
        <td>CVE-2019-13115</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.7.0-1+deb9u1</td>
        <td>1.7.0-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-13115">https://access.redhat.com/security/cve/CVE-2019-13115</a>
          <a href="https://blog.semmle.com/libssh2-integer-overflow/">https://blog.semmle.com/libssh2-integer-overflow/</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13115">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13115</a>
          <a href="https://github.com/libssh2/libssh2/compare/02ecf17...42d37aa">https://github.com/libssh2/libssh2/compare/02ecf17...42d37aa</a>
          <a href="https://github.com/libssh2/libssh2/pull/350">https://github.com/libssh2/libssh2/pull/350</a>
          <a href="https://libssh2.org/changes.html">https://libssh2.org/changes.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/07/msg00024.html">https://lists.debian.org/debian-lts-announce/2019/07/msg00024.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00013.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00013.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6LUNHPW64IGCASZ4JQ2J5KDXNZN53DWW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6LUNHPW64IGCASZ4JQ2J5KDXNZN53DWW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M7IF3LNHOA75O4WZWIHJLIRMA5LJUED3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M7IF3LNHOA75O4WZWIHJLIRMA5LJUED3/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190806-0002/">https://security.netapp.com/advisory/ntap-20190806-0002/</a>
          <a href="https://support.f5.com/csp/article/K13322484">https://support.f5.com/csp/article/K13322484</a>
          <a href="https://support.f5.com/csp/article/K13322484?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K13322484?utm_source=f5support&amp;amp;utm_medium=RSS</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssh2-1</td>
        <td>CVE-2019-17498</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.7.0-1+deb9u1</td>
        <td>1.7.0-1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00026.html">http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00026.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-17498">https://access.redhat.com/security/cve/CVE-2019-17498</a>
          <a href="https://blog.semmle.com/libssh2-integer-overflow-CVE-2019-17498/">https://blog.semmle.com/libssh2-integer-overflow-CVE-2019-17498/</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17498">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17498</a>
          <a href="https://github.com/kevinbackhouse/SecurityExploits/tree/8cbdbbe6363510f7d9ceec685373da12e6fc752d/libssh2/out_of_bounds_read_disconnect_CVE-2019-17498">https://github.com/kevinbackhouse/SecurityExploits/tree/8cbdbbe6363510f7d9ceec685373da12e6fc752d/libssh2/out_of_bounds_read_disconnect_CVE-2019-17498</a>
          <a href="https://github.com/libssh2/libssh2/blob/42d37aa63129a1b2644bf6495198923534322d64/src/packet.c#L480">https://github.com/libssh2/libssh2/blob/42d37aa63129a1b2644bf6495198923534322d64/src/packet.c#L480</a>
          <a href="https://github.com/libssh2/libssh2/commit/dedcbd106f8e52d5586b0205bc7677e4c9868f9c">https://github.com/libssh2/libssh2/commit/dedcbd106f8e52d5586b0205bc7677e4c9868f9c</a>
          <a href="https://github.com/libssh2/libssh2/pull/402/commits/1c6fa92b77e34d089493fe6d3e2c6c8775858b94">https://github.com/libssh2/libssh2/pull/402/commits/1c6fa92b77e34d089493fe6d3e2c6c8775858b94</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-17498.html">https://linux.oracle.com/cve/CVE-2019-17498.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-3915.html">https://linux.oracle.com/errata/ELSA-2020-3915.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/11/msg00010.html">https://lists.debian.org/debian-lts-announce/2019/11/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00013.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00013.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/22H4Q5XMGS3QNSA7OCL3U7UQZ4NXMR5O/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/22H4Q5XMGS3QNSA7OCL3U7UQZ4NXMR5O/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TY7EEE34RFKCTXTMBQQWWSLXZWSCXNDB/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TY7EEE34RFKCTXTMBQQWWSLXZWSCXNDB/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-17498">https://nvd.nist.gov/vuln/detail/CVE-2019-17498</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.0.2</td>
        <td>CVE-2021-23840</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.0.2t-1~deb9u1</td>
        <td>1.0.2u-1~deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23840">https://access.redhat.com/security/cve/CVE-2021-23840</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23840.html">https://linux.oracle.com/cve/CVE-2021-23840.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0057.html">https://rustsec.org/advisories/RUSTSEC-2021-0057.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.0.2</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.0.2t-1~deb9u1</td>
        <td>1.0.2u-1~deb9u6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3712">https://access.redhat.com/security/cve/CVE-2021-3712</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3712.html">https://linux.oracle.com/cve/CVE-2021-3712.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-9023.html">https://linux.oracle.com/errata/ELSA-2022-9023.html</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3712">https://nvd.nist.gov/vuln/detail/CVE-2021-3712</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0098.html">https://rustsec.org/advisories/RUSTSEC-2021-0098.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0010/">https://security.netapp.com/advisory/ntap-20210827-0010/</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-1">https://ubuntu.com/security/notices/USN-5051-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-2">https://ubuntu.com/security/notices/USN-5051-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-3">https://ubuntu.com/security/notices/USN-5051-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)">https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4963">https://www.debian.org/security/2021/dsa-4963</a>
          <a href="https://www.openssl.org/news/secadv/20210824.txt">https://www.openssl.org/news/secadv/20210824.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-16">https://www.tenable.com/security/tns-2021-16</a>
          <a href="https://www.tenable.com/security/tns-2022-02">https://www.tenable.com/security/tns-2022-02</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.0.2</td>
        <td>CVE-2019-1551</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.0.2t-1~deb9u1</td>
        <td>1.0.2u-1~deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00030.html">http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00030.html</a>
          <a href="http://packetstormsecurity.com/files/155754/Slackware-Security-Advisory-openssl-Updates.html">http://packetstormsecurity.com/files/155754/Slackware-Security-Advisory-openssl-Updates.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-1551">https://access.redhat.com/security/cve/CVE-2019-1551</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1551">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1551</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=419102400a2811582a7a3d4a4e317d72e5ce0a8f">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=419102400a2811582a7a3d4a4e317d72e5ce0a8f</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f1c5eea8a817075d31e43f5876993c6710238c98">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f1c5eea8a817075d31e43f5876993c6710238c98</a>
          <a href="https://github.com/openssl/openssl/pull/10575">https://github.com/openssl/openssl/pull/10575</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-1551.html">https://linux.oracle.com/cve/CVE-2019-1551.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4514.html">https://linux.oracle.com/errata/ELSA-2020-4514.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/</a>
          <a href="https://seclists.org/bugtraq/2019/Dec/39">https://seclists.org/bugtraq/2019/Dec/39</a>
          <a href="https://seclists.org/bugtraq/2019/Dec/46">https://seclists.org/bugtraq/2019/Dec/46</a>
          <a href="https://security.gentoo.org/glsa/202004-10">https://security.gentoo.org/glsa/202004-10</a>
          <a href="https://security.netapp.com/advisory/ntap-20191210-0001/">https://security.netapp.com/advisory/ntap-20191210-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4376-1">https://ubuntu.com/security/notices/USN-4376-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4504-1">https://ubuntu.com/security/notices/USN-4504-1</a>
          <a href="https://usn.ubuntu.com/4376-1/">https://usn.ubuntu.com/4376-1/</a>
          <a href="https://usn.ubuntu.com/4504-1/">https://usn.ubuntu.com/4504-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4594">https://www.debian.org/security/2019/dsa-4594</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20191206.txt">https://www.openssl.org/news/secadv/20191206.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.tenable.com/security/tns-2019-09">https://www.tenable.com/security/tns-2019-09</a>
          <a href="https://www.tenable.com/security/tns-2020-03">https://www.tenable.com/security/tns-2020-03</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.0.2</td>
        <td>CVE-2020-1971</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.0.2t-1~deb9u1</td>
        <td>1.0.2u-1~deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/09/14/2">http://www.openwall.com/lists/oss-security/2021/09/14/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-1971">https://access.redhat.com/security/cve/CVE-2020-1971</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1971.html">https://linux.oracle.com/cve/CVE-2020-1971.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9150.html">https://linux.oracle.com/errata/ELSA-2021-9150.html</a>
          <a href="https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E">https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1971">https://nvd.nist.gov/vuln/detail/CVE-2020-1971</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202012-13">https://security.gentoo.org/glsa/202012-13</a>
          <a href="https://security.netapp.com/advisory/ntap-20201218-0005/">https://security.netapp.com/advisory/ntap-20201218-0005/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4662-1">https://ubuntu.com/security/notices/USN-4662-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4807">https://www.debian.org/security/2020/dsa-4807</a>
          <a href="https://www.openssl.org/news/secadv/20201208.txt">https://www.openssl.org/news/secadv/20201208.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.0.2</td>
        <td>CVE-2021-23841</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.0.2t-1~deb9u1</td>
        <td>1.0.2u-1~deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/67">http://seclists.org/fulldisclosure/2021/May/67</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/68">http://seclists.org/fulldisclosure/2021/May/68</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-23841">https://access.redhat.com/security/cve/CVE-2021-23841</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23841.html">https://linux.oracle.com/cve/CVE-2021-23841.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0058.html">https://rustsec.org/advisories/RUSTSEC-2021-0058.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://support.apple.com/kb/HT212528">https://support.apple.com/kb/HT212528</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212534">https://support.apple.com/kb/HT212534</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-23840</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23840">https://access.redhat.com/security/cve/CVE-2021-23840</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23840.html">https://linux.oracle.com/cve/CVE-2021-23840.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0057.html">https://rustsec.org/advisories/RUSTSEC-2021-0057.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3712">https://access.redhat.com/security/cve/CVE-2021-3712</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3712.html">https://linux.oracle.com/cve/CVE-2021-3712.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-9023.html">https://linux.oracle.com/errata/ELSA-2022-9023.html</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3712">https://nvd.nist.gov/vuln/detail/CVE-2021-3712</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0098.html">https://rustsec.org/advisories/RUSTSEC-2021-0098.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0010/">https://security.netapp.com/advisory/ntap-20210827-0010/</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-1">https://ubuntu.com/security/notices/USN-5051-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-2">https://ubuntu.com/security/notices/USN-5051-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-3">https://ubuntu.com/security/notices/USN-5051-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)">https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4963">https://www.debian.org/security/2021/dsa-4963</a>
          <a href="https://www.openssl.org/news/secadv/20210824.txt">https://www.openssl.org/news/secadv/20210824.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-16">https://www.tenable.com/security/tns-2021-16</a>
          <a href="https://www.tenable.com/security/tns-2022-02">https://www.tenable.com/security/tns-2022-02</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2020-1971</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/09/14/2">http://www.openwall.com/lists/oss-security/2021/09/14/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-1971">https://access.redhat.com/security/cve/CVE-2020-1971</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1971.html">https://linux.oracle.com/cve/CVE-2020-1971.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9150.html">https://linux.oracle.com/errata/ELSA-2021-9150.html</a>
          <a href="https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E">https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1971">https://nvd.nist.gov/vuln/detail/CVE-2020-1971</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202012-13">https://security.gentoo.org/glsa/202012-13</a>
          <a href="https://security.netapp.com/advisory/ntap-20201218-0005/">https://security.netapp.com/advisory/ntap-20201218-0005/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4662-1">https://ubuntu.com/security/notices/USN-4662-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4807">https://www.debian.org/security/2020/dsa-4807</a>
          <a href="https://www.openssl.org/news/secadv/20201208.txt">https://www.openssl.org/news/secadv/20201208.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-23841</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/67">http://seclists.org/fulldisclosure/2021/May/67</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/68">http://seclists.org/fulldisclosure/2021/May/68</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-23841">https://access.redhat.com/security/cve/CVE-2021-23841</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23841.html">https://linux.oracle.com/cve/CVE-2021-23841.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0058.html">https://rustsec.org/advisories/RUSTSEC-2021-0058.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://support.apple.com/kb/HT212528">https://support.apple.com/kb/HT212528</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212534">https://support.apple.com/kb/HT212534</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libstdc++6</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">6.3.0-18+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-12886">https://access.redhat.com/security/cve/CVE-2018-12886</a>
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2019-3843</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108116">http://www.securityfocus.com/bid/108116</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-3843">https://access.redhat.com/security/cve/CVE-2019-3843</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843</a>
          <a href="https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)">https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3843.html">https://linux.oracle.com/cve/CVE-2019-3843.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3843">https://nvd.nist.gov/vuln/detail/CVE-2019-3843</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2019-3844</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108096">http://www.securityfocus.com/bid/108096</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-3844">https://access.redhat.com/security/cve/CVE-2019-3844</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3844.html">https://linux.oracle.com/cve/CVE-2019-3844.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3844">https://nvd.nist.gov/vuln/detail/CVE-2019-3844</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2020-1712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1712">https://access.redhat.com/security/cve/CVE-2020-1712</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712</a>
          <a href="https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54">https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54</a>
          <a href="https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb">https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb</a>
          <a href="https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d">https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d</a>
          <a href="https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2">https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1712.html">https://linux.oracle.com/cve/CVE-2020-1712.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-0575.html">https://linux.oracle.com/errata/ELSA-2020-0575.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1712">https://nvd.nist.gov/vuln/detail/CVE-2020-1712</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/02/05/1">https://www.openwall.com/lists/oss-security/2020/02/05/1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2021-33910</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td>232-25+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html">http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/04/2">http://www.openwall.com/lists/oss-security/2021/08/04/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/3">http://www.openwall.com/lists/oss-security/2021/08/17/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/07/3">http://www.openwall.com/lists/oss-security/2021/09/07/3</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-33910">https://access.redhat.com/security/cve/CVE-2021-33910</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910</a>
          <a href="https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b">https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b</a>
          <a href="https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce">https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce</a>
          <a href="https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538">https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538</a>
          <a href="https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61">https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61</a>
          <a href="https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b">https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b</a>
          <a href="https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9">https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33910.html">https://linux.oracle.com/cve/CVE-2021-33910.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-2717.html">https://linux.oracle.com/errata/ELSA-2021-2717.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33910">https://nvd.nist.gov/vuln/detail/CVE-2021-33910</a>
          <a href="https://security.gentoo.org/glsa/202107-48">https://security.gentoo.org/glsa/202107-48</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0008/">https://security.netapp.com/advisory/ntap-20211104-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5013-1">https://ubuntu.com/security/notices/USN-5013-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5013-2">https://ubuntu.com/security/notices/USN-5013-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4942">https://www.debian.org/security/2021/dsa-4942</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/07/20/2">https://www.openwall.com/lists/oss-security/2021/07/20/2</a>
          <a href="https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt">https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2021-3997</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3997">https://access.redhat.com/security/cve/CVE-2021-3997</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997</a>
          <a href="https://ubuntu.com/security/notices/USN-5226-1">https://ubuntu.com/security/notices/USN-5226-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/10/2">https://www.openwall.com/lists/oss-security/2022/01/10/2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2019-3843</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108116">http://www.securityfocus.com/bid/108116</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-3843">https://access.redhat.com/security/cve/CVE-2019-3843</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843</a>
          <a href="https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)">https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3843.html">https://linux.oracle.com/cve/CVE-2019-3843.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3843">https://nvd.nist.gov/vuln/detail/CVE-2019-3843</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2019-3844</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108096">http://www.securityfocus.com/bid/108096</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-3844">https://access.redhat.com/security/cve/CVE-2019-3844</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3844.html">https://linux.oracle.com/cve/CVE-2019-3844.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3844">https://nvd.nist.gov/vuln/detail/CVE-2019-3844</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2020-1712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1712">https://access.redhat.com/security/cve/CVE-2020-1712</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1712</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1712</a>
          <a href="https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54">https://github.com/systemd/systemd/commit/1068447e6954dc6ce52f099ed174c442cb89ed54</a>
          <a href="https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb">https://github.com/systemd/systemd/commit/637486261528e8aa3da9f26a4487dc254f4b7abb</a>
          <a href="https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d">https://github.com/systemd/systemd/commit/bc130b6858327b382b07b3985cf48e2aa9016b2d</a>
          <a href="https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2">https://github.com/systemd/systemd/commit/ea0d0ede03c6f18dbc5036c5e9cccf97e415ccc2</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1712.html">https://linux.oracle.com/cve/CVE-2020-1712.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-0575.html">https://linux.oracle.com/errata/ELSA-2020-0575.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1712">https://nvd.nist.gov/vuln/detail/CVE-2020-1712</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/02/05/1">https://www.openwall.com/lists/oss-security/2020/02/05/1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2021-33910</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td>232-25+deb9u13</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html">http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/04/2">http://www.openwall.com/lists/oss-security/2021/08/04/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/3">http://www.openwall.com/lists/oss-security/2021/08/17/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/07/3">http://www.openwall.com/lists/oss-security/2021/09/07/3</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-33910">https://access.redhat.com/security/cve/CVE-2021-33910</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33910</a>
          <a href="https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b">https://github.com/systemd/systemd-stable/commit/4a1c5f34bd3e1daed4490e9d97918e504d19733b</a>
          <a href="https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce">https://github.com/systemd/systemd-stable/commit/764b74113e36ac5219a4b82a05f311b5a92136ce</a>
          <a href="https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538">https://github.com/systemd/systemd-stable/commit/b00674347337b7531c92fdb65590ab253bb57538</a>
          <a href="https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61">https://github.com/systemd/systemd-stable/commit/cfd14c65374027b34dbbc4f0551456c5dc2d1f61</a>
          <a href="https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b">https://github.com/systemd/systemd/commit/b34a4f0e6729de292cb3b0c03c1d48f246ad896b</a>
          <a href="https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9">https://github.com/systemd/systemd/pull/20256/commits/441e0115646d54f080e5c3bb0ba477c892861ab9</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33910.html">https://linux.oracle.com/cve/CVE-2021-33910.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-2717.html">https://linux.oracle.com/errata/ELSA-2021-2717.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2LSDMHAKI4LGFOCSPXNVVSEWQFAVFWR7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33910">https://nvd.nist.gov/vuln/detail/CVE-2021-33910</a>
          <a href="https://security.gentoo.org/glsa/202107-48">https://security.gentoo.org/glsa/202107-48</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0008/">https://security.netapp.com/advisory/ntap-20211104-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5013-1">https://ubuntu.com/security/notices/USN-5013-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5013-2">https://ubuntu.com/security/notices/USN-5013-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4942">https://www.debian.org/security/2021/dsa-4942</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/07/20/2">https://www.openwall.com/lists/oss-security/2021/07/20/2</a>
          <a href="https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt">https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2021-3997</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">232-25+deb9u12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3997">https://access.redhat.com/security/cve/CVE-2021-3997</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997</a>
          <a href="https://ubuntu.com/security/notices/USN-5226-1">https://ubuntu.com/security/notices/USN-5226-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/10/2">https://www.openwall.com/lists/oss-security/2022/01/10/2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libuuid1</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2018-6485</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://bugs.debian.org/878159">http://bugs.debian.org/878159</a>
          <a href="http://www.securityfocus.com/bid/102912">http://www.securityfocus.com/bid/102912</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3092">https://access.redhat.com/errata/RHSA-2018:3092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-6485">https://access.redhat.com/security/cve/CVE-2018-6485</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-6485.html">https://linux.oracle.com/cve/CVE-2018-6485.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3092.html">https://linux.oracle.com/errata/ELSA-2018-3092.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22343">https://sourceware.org/bugzilla/show_bug.cgi?id=22343</a>
          <a href="https://ubuntu.com/security/notices/USN-4218-1">https://ubuntu.com/security/notices/USN-4218-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4218-1/">https://usn.ubuntu.com/4218-1/</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html">https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2018-6551</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-6551">https://access.redhat.com/security/cve/CVE-2018-6551</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22774">https://sourceware.org/bugzilla/show_bug.cgi?id=22774</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22">https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2019-9169</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/107160">http://www.securityfocus.com/bid/107160</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9169">https://access.redhat.com/security/cve/CVE-2019-9169</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9169.html">https://linux.oracle.com/cve/CVE-2019-9169.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9169">https://nvd.nist.gov/vuln/detail/CVE-2019-9169</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24114">https://sourceware.org/bugzilla/show_bug.cgi?id=24114</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9</a>
          <a href="https://support.f5.com/csp/article/K54823184">https://support.f5.com/csp/article/K54823184</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33574">https://access.redhat.com/security/cve/CVE-2021-33574</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33574">https://nvd.nist.gov/vuln/detail/CVE-2021-33574</a>
          <a href="https://security.gentoo.org/glsa/202107-07">https://security.gentoo.org/glsa/202107-07</a>
          <a href="https://security.netapp.com/advisory/ntap-20210629-0005/">https://security.netapp.com/advisory/ntap-20210629-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896">https://sourceware.org/bugzilla/show_bug.cgi?id=27896</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1">https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-35942</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-35942">https://access.redhat.com/security/cve/CVE-2021-35942</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35942">https://nvd.nist.gov/vuln/detail/CVE-2021-35942</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0005/">https://security.netapp.com/advisory/ntap-20210827-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28011">https://sourceware.org/bugzilla/show_bug.cgi?id=28011</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c">https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c</a>
          <a href="https://sourceware.org/glibc/wiki/Security%20Exceptions">https://sourceware.org/glibc/wiki/Security%20Exceptions</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2022-23218</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">locales</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2009-5155</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272">http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272</a>
          <a href="https://access.redhat.com/security/cve/CVE-2009-5155">https://access.redhat.com/security/cve/CVE-2009-5155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=11053">https://sourceware.org/bugzilla/show_bug.cgi?id=11053</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18986">https://sourceware.org/bugzilla/show_bug.cgi?id=18986</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672</a>
          <a href="https://support.f5.com/csp/article/K64119434">https://support.f5.com/csp/article/K64119434</a>
          <a href="https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4954-1">https://ubuntu.com/security/notices/USN-4954-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2018-1000001</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2018/q1/38">http://seclists.org/oss-sec/2018/q1/38</a>
          <a href="http://www.openwall.com/lists/oss-security/2018/01/11/5">http://www.openwall.com/lists/oss-security/2018/01/11/5</a>
          <a href="http://www.securityfocus.com/bid/102525">http://www.securityfocus.com/bid/102525</a>
          <a href="http://www.securitytracker.com/id/1040162">http://www.securitytracker.com/id/1040162</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000001">https://access.redhat.com/security/cve/CVE-2018-1000001</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-1000001.html">https://linux.oracle.com/cve/CVE-2018-1000001.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://lists.samba.org/archive/rsync/2018-February/031478.html">https://lists.samba.org/archive/rsync/2018-February/031478.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18203">https://sourceware.org/bugzilla/show_bug.cgi?id=18203</a>
          <a href="https://ubuntu.com/security/notices/USN-3534-1">https://ubuntu.com/security/notices/USN-3534-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3536-1">https://ubuntu.com/security/notices/USN-3536-1</a>
          <a href="https://usn.ubuntu.com/3534-1/">https://usn.ubuntu.com/3534-1/</a>
          <a href="https://usn.ubuntu.com/3536-1/">https://usn.ubuntu.com/3536-1/</a>
          <a href="https://www.exploit-db.com/exploits/43775/">https://www.exploit-db.com/exploits/43775/</a>
          <a href="https://www.exploit-db.com/exploits/44889/">https://www.exploit-db.com/exploits/44889/</a>
          <a href="https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/">https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1751">https://access.redhat.com/security/cve/CVE-2020-1751</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1751">https://nvd.nist.gov/vuln/detail/CVE-2020-1751</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200430-0002/">https://security.netapp.com/advisory/ntap-20200430-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25423">https://sourceware.org/bugzilla/show_bug.cgi?id=25423</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2020-1752</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1752">https://access.redhat.com/security/cve/CVE-2020-1752</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1752">https://nvd.nist.gov/vuln/detail/CVE-2020-1752</a>
          <a href="https://security.gentoo.org/glsa/202101-20">https://security.gentoo.org/glsa/202101-20</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0005/">https://security.netapp.com/advisory/ntap-20200511-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25414">https://sourceware.org/bugzilla/show_bug.cgi?id=25414</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-3326</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3326">https://access.redhat.com/security/cve/CVE-2021-3326</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3326">https://nvd.nist.gov/vuln/detail/CVE-2021-3326</a>
          <a href="https://security.netapp.com/advisory/ntap-20210304-0007/">https://security.netapp.com/advisory/ntap-20210304-0007/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27256">https://sourceware.org/bugzilla/show_bug.cgi?id=27256</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888">https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888</a>
          <a href="https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html">https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-3999</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2016-10739</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html</a>
          <a href="http://www.securityfocus.com/bid/106672">http://www.securityfocus.com/bid/106672</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2118">https://access.redhat.com/errata/RHSA-2019:2118</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3513">https://access.redhat.com/errata/RHSA-2019:3513</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-10739">https://access.redhat.com/security/cve/CVE-2016-10739</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1347549">https://bugzilla.redhat.com/show_bug.cgi?id=1347549</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739</a>
          <a href="https://linux.oracle.com/cve/CVE-2016-10739.html">https://linux.oracle.com/cve/CVE-2016-10739.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3513.html">https://linux.oracle.com/errata/ELSA-2019-3513.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-10739">https://nvd.nist.gov/vuln/detail/CVE-2016-10739</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=20018">https://sourceware.org/bugzilla/show_bug.cgi?id=20018</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2017-12132</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/100598">http://www.securityfocus.com/bid/100598</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-12132">https://access.redhat.com/security/cve/CVE-2017-12132</a>
          <a href="https://arxiv.org/pdf/1205.4011.pdf">https://arxiv.org/pdf/1205.4011.pdf</a>
          <a href="https://linux.oracle.com/cve/CVE-2017-12132.html">https://linux.oracle.com/cve/CVE-2017-12132.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=21361">https://sourceware.org/bugzilla/show_bug.cgi?id=21361</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-25013">https://access.redhat.com/security/cve/CVE-2019-25013</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-25013.html">https://linux.oracle.com/cve/CVE-2019-25013.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-25013">https://nvd.nist.gov/vuln/detail/CVE-2019-25013</a>
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10029">https://access.redhat.com/security/cve/CVE-2020-10029</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10029">https://nvd.nist.gov/vuln/detail/CVE-2020-10029</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200327-0003/">https://security.netapp.com/advisory/ntap-20200327-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25487">https://sourceware.org/bugzilla/show_bug.cgi?id=25487</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2020-27618</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27618">https://access.redhat.com/security/cve/CVE-2020-27618</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-27618">https://nvd.nist.gov/vuln/detail/CVE-2020-27618</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3998">https://access.redhat.com/security/cve/CVE-2021-3998</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">login</td>
        <td>CVE-2017-12424</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1:4.4-4.1</td>
        <td>1:4.4-4.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2017-12424">https://access.redhat.com/security/cve/CVE-2017-12424</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630</a>
          <a href="https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675">https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675</a>
          <a href="https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952">https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html</a>
          <a href="https://security.gentoo.org/glsa/201710-16">https://security.gentoo.org/glsa/201710-16</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">login</td>
        <td>CVE-2017-20002</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1:4.4-4.1</td>
        <td>1:4.4-4.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">mount</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2018-6485</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://bugs.debian.org/878159">http://bugs.debian.org/878159</a>
          <a href="http://www.securityfocus.com/bid/102912">http://www.securityfocus.com/bid/102912</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:3092">https://access.redhat.com/errata/RHSA-2018:3092</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-6485">https://access.redhat.com/security/cve/CVE-2018-6485</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6485</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-6485.html">https://linux.oracle.com/cve/CVE-2018-6485.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-3092.html">https://linux.oracle.com/errata/ELSA-2018-3092.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22343">https://sourceware.org/bugzilla/show_bug.cgi?id=22343</a>
          <a href="https://ubuntu.com/security/notices/USN-4218-1">https://ubuntu.com/security/notices/USN-4218-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4218-1/">https://usn.ubuntu.com/4218-1/</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html">https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2018-6551</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2018-6551">https://access.redhat.com/security/cve/CVE-2018-6551</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22774">https://sourceware.org/bugzilla/show_bug.cgi?id=22774</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22">https://sourceware.org/git/?p=glibc.git;a=commit;h=8e448310d74b283c5cd02b9ed7fb997b47bf9b22</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2019-9169</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/107160">http://www.securityfocus.com/bid/107160</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9169">https://access.redhat.com/security/cve/CVE-2019-9169</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9169</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34140</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34142</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10278</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9169.html">https://linux.oracle.com/cve/CVE-2019-9169.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9169">https://nvd.nist.gov/vuln/detail/CVE-2019-9169</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24114">https://sourceware.org/bugzilla/show_bug.cgi?id=24114</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9</a>
          <a href="https://support.f5.com/csp/article/K54823184">https://support.f5.com/csp/article/K54823184</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33574">https://access.redhat.com/security/cve/CVE-2021-33574</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33574">https://nvd.nist.gov/vuln/detail/CVE-2021-33574</a>
          <a href="https://security.gentoo.org/glsa/202107-07">https://security.gentoo.org/glsa/202107-07</a>
          <a href="https://security.netapp.com/advisory/ntap-20210629-0005/">https://security.netapp.com/advisory/ntap-20210629-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896">https://sourceware.org/bugzilla/show_bug.cgi?id=27896</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1">https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-35942</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-35942.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-35942">https://access.redhat.com/security/cve/CVE-2021-35942</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35942">https://nvd.nist.gov/vuln/detail/CVE-2021-35942</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0005/">https://security.netapp.com/advisory/ntap-20210827-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28011">https://sourceware.org/bugzilla/show_bug.cgi?id=28011</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c">https://sourceware.org/git/?p=glibc.git;a=commit;h=5adda61f62b77384718b4c0d8336ade8f2b4b35c</a>
          <a href="https://sourceware.org/glibc/wiki/Security%20Exceptions">https://sourceware.org/glibc/wiki/Security%20Exceptions</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2022-23218</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2009-5155</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272">http://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=5513b40999149090987a0341c018d05d3eea1272</a>
          <a href="https://access.redhat.com/security/cve/CVE-2009-5155">https://access.redhat.com/security/cve/CVE-2009-5155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806</a>
          <a href="https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238">https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190315-0002/">https://security.netapp.com/advisory/ntap-20190315-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=11053">https://sourceware.org/bugzilla/show_bug.cgi?id=11053</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18986">https://sourceware.org/bugzilla/show_bug.cgi?id=18986</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=eb04c21373e2a2885f3d52ff192b0499afe3c672</a>
          <a href="https://support.f5.com/csp/article/K64119434">https://support.f5.com/csp/article/K64119434</a>
          <a href="https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K64119434?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4954-1">https://ubuntu.com/security/notices/USN-4954-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2018-1000001</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2018/q1/38">http://seclists.org/oss-sec/2018/q1/38</a>
          <a href="http://www.openwall.com/lists/oss-security/2018/01/11/5">http://www.openwall.com/lists/oss-security/2018/01/11/5</a>
          <a href="http://www.securityfocus.com/bid/102525">http://www.securityfocus.com/bid/102525</a>
          <a href="http://www.securitytracker.com/id/1040162">http://www.securitytracker.com/id/1040162</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-1000001">https://access.redhat.com/security/cve/CVE-2018-1000001</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000001</a>
          <a href="https://linux.oracle.com/cve/CVE-2018-1000001.html">https://linux.oracle.com/cve/CVE-2018-1000001.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://lists.samba.org/archive/rsync/2018-February/031478.html">https://lists.samba.org/archive/rsync/2018-February/031478.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20190404-0003/">https://security.netapp.com/advisory/ntap-20190404-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=18203">https://sourceware.org/bugzilla/show_bug.cgi?id=18203</a>
          <a href="https://ubuntu.com/security/notices/USN-3534-1">https://ubuntu.com/security/notices/USN-3534-1</a>
          <a href="https://ubuntu.com/security/notices/USN-3536-1">https://ubuntu.com/security/notices/USN-3536-1</a>
          <a href="https://usn.ubuntu.com/3534-1/">https://usn.ubuntu.com/3534-1/</a>
          <a href="https://usn.ubuntu.com/3536-1/">https://usn.ubuntu.com/3536-1/</a>
          <a href="https://www.exploit-db.com/exploits/43775/">https://www.exploit-db.com/exploits/43775/</a>
          <a href="https://www.exploit-db.com/exploits/44889/">https://www.exploit-db.com/exploits/44889/</a>
          <a href="https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/">https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1751">https://access.redhat.com/security/cve/CVE-2020-1751</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1751">https://nvd.nist.gov/vuln/detail/CVE-2020-1751</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200430-0002/">https://security.netapp.com/advisory/ntap-20200430-0002/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25423">https://sourceware.org/bugzilla/show_bug.cgi?id=25423</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2020-1752</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-1752">https://access.redhat.com/security/cve/CVE-2020-1752</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1752">https://nvd.nist.gov/vuln/detail/CVE-2020-1752</a>
          <a href="https://security.gentoo.org/glsa/202101-20">https://security.gentoo.org/glsa/202101-20</a>
          <a href="https://security.netapp.com/advisory/ntap-20200511-0005/">https://security.netapp.com/advisory/ntap-20200511-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25414">https://sourceware.org/bugzilla/show_bug.cgi?id=25414</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c">https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=ddc650e9b3dc916eab417ce9f79e67337b05035c</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-3326</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3326">https://access.redhat.com/security/cve/CVE-2021-3326</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3326">https://nvd.nist.gov/vuln/detail/CVE-2021-3326</a>
          <a href="https://security.netapp.com/advisory/ntap-20210304-0007/">https://security.netapp.com/advisory/ntap-20210304-0007/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=27256">https://sourceware.org/bugzilla/show_bug.cgi?id=27256</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888">https://sourceware.org/git/?p=glibc.git;a=commit;h=7d88c6142c6efc160c0ee5e4f85cde382c072888</a>
          <a href="https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html">https://sourceware.org/pipermail/libc-alpha/2021-January/122058.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-3999</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2016-10739</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00082.html</a>
          <a href="http://www.securityfocus.com/bid/106672">http://www.securityfocus.com/bid/106672</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2118">https://access.redhat.com/errata/RHSA-2019:2118</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3513">https://access.redhat.com/errata/RHSA-2019:3513</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-10739">https://access.redhat.com/security/cve/CVE-2016-10739</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1347549">https://bugzilla.redhat.com/show_bug.cgi?id=1347549</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10739</a>
          <a href="https://linux.oracle.com/cve/CVE-2016-10739.html">https://linux.oracle.com/cve/CVE-2016-10739.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-3513.html">https://linux.oracle.com/errata/ELSA-2019-3513.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-10739">https://nvd.nist.gov/vuln/detail/CVE-2016-10739</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=20018">https://sourceware.org/bugzilla/show_bug.cgi?id=20018</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2017-12132</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/100598">http://www.securityfocus.com/bid/100598</a>
          <a href="https://access.redhat.com/errata/RHSA-2018:0805">https://access.redhat.com/errata/RHSA-2018:0805</a>
          <a href="https://access.redhat.com/security/cve/CVE-2017-12132">https://access.redhat.com/security/cve/CVE-2017-12132</a>
          <a href="https://arxiv.org/pdf/1205.4011.pdf">https://arxiv.org/pdf/1205.4011.pdf</a>
          <a href="https://linux.oracle.com/cve/CVE-2017-12132.html">https://linux.oracle.com/cve/CVE-2017-12132.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2018-0805.html">https://linux.oracle.com/errata/ELSA-2018-0805.html</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=21361">https://sourceware.org/bugzilla/show_bug.cgi?id=21361</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-25013">https://access.redhat.com/security/cve/CVE-2019-25013</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25013</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-25013.html">https://linux.oracle.com/cve/CVE-2019-25013.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r32d767ac804e9b8aad4355bb85960a6a1385eab7afff549a5e98660f@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r448bb851cc8e6e3f93f3c28c70032b37062625d81214744474ac49e7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r4806a391091e082bdea17266452ca656ebc176e51bb3932733b3a0a2@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r499e4f96d0b5109ef083f2feccd33c51650c1b7d7068aa3bd47efca9@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E">https://lists.apache.org/thread.html/r5af4430421bb6f9973294691a7904bbd260937e9eef96b20556f43ff@%3Cjira.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r750eee18542bc02bd8350861c424ee60a9b9b225568fa09436a37ece@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r7a2e94adfe0a2f0a1d42e4927e8c32ecac97d37db9cb68095fe9ddbc@%3Cdev.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rd2354f9ccce41e494fbadcbc5ad87218de6ec0fff8a7b54c8462226c@%3Cissues.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TVCUNLQ3HXGS4VPUQKWTJGRAW2KTFGXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-25013">https://nvd.nist.gov/vuln/detail/CVE-2019-25013</a>
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10029">https://access.redhat.com/security/cve/CVE-2020-10029</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10029">https://nvd.nist.gov/vuln/detail/CVE-2020-10029</a>
          <a href="https://security.gentoo.org/glsa/202006-04">https://security.gentoo.org/glsa/202006-04</a>
          <a href="https://security.netapp.com/advisory/ntap-20200327-0003/">https://security.netapp.com/advisory/ntap-20200327-0003/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=25487">https://sourceware.org/bugzilla/show_bug.cgi?id=25487</a>
          <a href="https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f">https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=9333498794cde1d5cca518badf79533a24114b6f</a>
          <a href="https://ubuntu.com/security/notices/USN-4416-1">https://ubuntu.com/security/notices/USN-4416-1</a>
          <a href="https://usn.ubuntu.com/4416-1/">https://usn.ubuntu.com/4416-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2020-27618</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27618">https://access.redhat.com/security/cve/CVE-2020-27618</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-27618">https://nvd.nist.gov/vuln/detail/CVE-2020-27618</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.24-11+deb9u4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3998">https://access.redhat.com/security/cve/CVE-2021-3998</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-23840</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23840">https://access.redhat.com/security/cve/CVE-2021-23840</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23840</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23840.html">https://linux.oracle.com/cve/CVE-2021-23840.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0057.html">https://rustsec.org/advisories/RUSTSEC-2021-0057.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u4</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3712.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3712">https://access.redhat.com/security/cve/CVE-2021-3712</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3712</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=94d23fcff9b2a7a8368dfe52214d5c2569882c11</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ccb0a11145ee72b042d10593a64eaf9e8a55ec12</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10366</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3712.html">https://linux.oracle.com/cve/CVE-2021-3712.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-9023.html">https://linux.oracle.com/errata/ELSA-2022-9023.html</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00021.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3712">https://nvd.nist.gov/vuln/detail/CVE-2021-3712</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0098.html">https://rustsec.org/advisories/RUSTSEC-2021-0098.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0010/">https://security.netapp.com/advisory/ntap-20210827-0010/</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-1">https://ubuntu.com/security/notices/USN-5051-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-2">https://ubuntu.com/security/notices/USN-5051-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-3">https://ubuntu.com/security/notices/USN-5051-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)">https://ubuntu.com/security/notices/USN-5051-4 (regression only in trusty/esm)</a>
          <a href="https://ubuntu.com/security/notices/USN-5088-1">https://ubuntu.com/security/notices/USN-5088-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4963">https://www.debian.org/security/2021/dsa-4963</a>
          <a href="https://www.openssl.org/news/secadv/20210824.txt">https://www.openssl.org/news/secadv/20210824.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-16">https://www.tenable.com/security/tns-2021-16</a>
          <a href="https://www.tenable.com/security/tns-2022-02">https://www.tenable.com/security/tns-2022-02</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">openssl</td>
        <td>CVE-2020-1971</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/09/14/2">http://www.openwall.com/lists/oss-security/2021/09/14/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-1971">https://access.redhat.com/security/cve/CVE-2020-1971</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2154ab83e14ede338d2ede9bbe5cdfce5d5a6c9e</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f960d81215ebf3f65e03d4d5d857fb9b666d6920</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44676</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1971.html">https://linux.oracle.com/cve/CVE-2020-1971.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9150.html">https://linux.oracle.com/errata/ELSA-2021-9150.html</a>
          <a href="https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r63c6f2dd363d9b514d0a4bcf624580616a679898cc14c109a49b750c@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E">https://lists.apache.org/thread.html/rbb769f771711fb274e0a4acb1b5911c8aab544a6ac5e8c12d40c5143@%3Ccommits.pulsar.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00021.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DGSI34Y5LQ5RYXN4M2I5ZQT65LFVDOUU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PWPSSZNZOBJU2YR6Z4TGHXKYW3YP5QG7/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1971">https://nvd.nist.gov/vuln/detail/CVE-2020-1971</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:33.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202012-13">https://security.gentoo.org/glsa/202012-13</a>
          <a href="https://security.netapp.com/advisory/ntap-20201218-0005/">https://security.netapp.com/advisory/ntap-20201218-0005/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4662-1">https://ubuntu.com/security/notices/USN-4662-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2020/dsa-4807">https://www.debian.org/security/2020/dsa-4807</a>
          <a href="https://www.openssl.org/news/secadv/20201208.txt">https://www.openssl.org/news/secadv/20201208.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-23841</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.0l-1~deb9u1</td>
        <td>1.1.0l-1~deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/May/67">http://seclists.org/fulldisclosure/2021/May/67</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/68">http://seclists.org/fulldisclosure/2021/May/68</a>
          <a href="http://seclists.org/fulldisclosure/2021/May/70">http://seclists.org/fulldisclosure/2021/May/70</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-23841">https://access.redhat.com/security/cve/CVE-2021-23841</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23841</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=122a19ab48091c657f7cb1fb3af9fc07bd557bbf</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44846</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23841.html">https://linux.oracle.com/cve/CVE-2021-23841.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9561.html">https://linux.oracle.com/errata/ELSA-2021-9561.html</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0058.html">https://rustsec.org/advisories/RUSTSEC-2021-0058.html</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210219-0009/">https://security.netapp.com/advisory/ntap-20210219-0009/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://support.apple.com/kb/HT212528">https://support.apple.com/kb/HT212528</a>
          <a href="https://support.apple.com/kb/HT212529">https://support.apple.com/kb/HT212529</a>
          <a href="https://support.apple.com/kb/HT212534">https://support.apple.com/kb/HT212534</a>
          <a href="https://ubuntu.com/security/notices/USN-4738-1">https://ubuntu.com/security/notices/USN-4738-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4745-1">https://ubuntu.com/security/notices/USN-4745-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4855">https://www.debian.org/security/2021/dsa-4855</a>
          <a href="https://www.openssl.org/news/secadv/20210216.txt">https://www.openssl.org/news/secadv/20210216.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-03">https://www.tenable.com/security/tns-2021-03</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">passwd</td>
        <td>CVE-2017-12424</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1:4.4-4.1</td>
        <td>1:4.4-4.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2017-12424">https://access.redhat.com/security/cve/CVE-2017-12424</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=756630</a>
          <a href="https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675">https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1266675</a>
          <a href="https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952">https://github.com/shadow-maint/shadow/commit/954e3d2e7113e9ac06632aee3c69b8d818cc8952</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html</a>
          <a href="https://security.gentoo.org/glsa/201710-16">https://security.gentoo.org/glsa/201710-16</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">passwd</td>
        <td>CVE-2017-20002</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1:4.4-4.1</td>
        <td>1:4.4-4.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877374</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=914957</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-10543</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.24.1-3+deb9u5</td>
        <td>5.24.1-3+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10543">https://access.redhat.com/security/cve/CVE-2020-10543</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10543">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10543</a>
          <a href="https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod">https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod</a>
          <a href="https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3">https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3</a>
          <a href="https://github.com/perl/perl5/commit/897d1f7fd515b828e4b198d8b8bef76c6faf03ed">https://github.com/perl/perl5/commit/897d1f7fd515b828e4b198d8b8bef76c6faf03ed</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10543.html">https://linux.oracle.com/cve/CVE-2020-10543.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9238.html">https://linux.oracle.com/errata/ELSA-2021-9238.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod</a>
          <a href="https://security.gentoo.org/glsa/202006-03">https://security.gentoo.org/glsa/202006-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20200611-0001/">https://security.netapp.com/advisory/ntap-20200611-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-1">https://ubuntu.com/security/notices/USN-4602-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-2">https://ubuntu.com/security/notices/USN-4602-2</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-10878</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.24.1-3+deb9u5</td>
        <td>5.24.1-3+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-10878">https://access.redhat.com/security/cve/CVE-2020-10878</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10878">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10878</a>
          <a href="https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod">https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod</a>
          <a href="https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3">https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3</a>
          <a href="https://github.com/perl/perl5/commit/0a320d753fe7fca03df259a4dfd8e641e51edaa8">https://github.com/perl/perl5/commit/0a320d753fe7fca03df259a4dfd8e641e51edaa8</a>
          <a href="https://github.com/perl/perl5/commit/3295b48defa0f8570114877b063fe546dd348b3c">https://github.com/perl/perl5/commit/3295b48defa0f8570114877b063fe546dd348b3c</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10878.html">https://linux.oracle.com/cve/CVE-2020-10878.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9238.html">https://linux.oracle.com/errata/ELSA-2021-9238.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod</a>
          <a href="https://security.gentoo.org/glsa/202006-03">https://security.gentoo.org/glsa/202006-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20200611-0001/">https://security.netapp.com/advisory/ntap-20200611-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-1">https://ubuntu.com/security/notices/USN-4602-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-2">https://ubuntu.com/security/notices/USN-4602-2</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-12723</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.24.1-3+deb9u5</td>
        <td>5.24.1-3+deb9u7</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-12723">https://access.redhat.com/security/cve/CVE-2020-12723</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12723">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12723</a>
          <a href="https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod">https://github.com/Perl/perl5/blob/blead/pod/perl5303delta.pod</a>
          <a href="https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3">https://github.com/Perl/perl5/compare/v5.30.2...v5.30.3</a>
          <a href="https://github.com/Perl/perl5/issues/16947">https://github.com/Perl/perl5/issues/16947</a>
          <a href="https://github.com/Perl/perl5/issues/17743">https://github.com/Perl/perl5/issues/17743</a>
          <a href="https://github.com/perl/perl5/commit/66bbb51b93253a3f87d11c2695cfb7bdb782184a">https://github.com/perl/perl5/commit/66bbb51b93253a3f87d11c2695cfb7bdb782184a</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-12723.html">https://linux.oracle.com/cve/CVE-2020-12723.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9238.html">https://linux.oracle.com/errata/ELSA-2021-9238.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IN3TTBO5KSGWE5IRIKDJ5JSQRH7ANNXE/</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.28.3/pod/perldelta.pod</a>
          <a href="https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod">https://metacpan.org/pod/release/XSAWYERX/perl-5.30.3/pod/perldelta.pod</a>
          <a href="https://security.gentoo.org/glsa/202006-03">https://security.gentoo.org/glsa/202006-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20200611-0001/">https://security.netapp.com/advisory/ntap-20200611-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-1">https://ubuntu.com/security/notices/USN-4602-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4602-2">https://ubuntu.com/security/notices/USN-4602-2</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-16156</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.24.1-3+deb9u5</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html">http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-16156">https://access.redhat.com/security/cve/CVE-2020-16156</a>
          <a href="https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/">https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156</a>
          <a href="https://github.com/andk/cpanpm/commit/b27c51adf0fda25dee84cb72cb2b1bf7d832148c">https://github.com/andk/cpanpm/commit/b27c51adf0fda25dee84cb72cb2b1bf7d832148c</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/</a>
          <a href="https://metacpan.org/pod/distribution/CPAN/scripts/cpan">https://metacpan.org/pod/distribution/CPAN/scripts/cpan</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">sudo</td>
        <td>CVE-2019-14287</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.8.19p1-2.1</td>
        <td>1.8.19p1-2.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00042.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00042.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00047.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00047.html</a>
          <a href="http://packetstormsecurity.com/files/154853/Slackware-Security-Advisory-sudo-Updates.html">http://packetstormsecurity.com/files/154853/Slackware-Security-Advisory-sudo-Updates.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/10/14/1">http://www.openwall.com/lists/oss-security/2019/10/14/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/10/24/1">http://www.openwall.com/lists/oss-security/2019/10/24/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/10/29/3">http://www.openwall.com/lists/oss-security/2019/10/29/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/14/2">http://www.openwall.com/lists/oss-security/2021/09/14/2</a>
          <a href="https://access.redhat.com/errata/RHBA-2019:3248">https://access.redhat.com/errata/RHBA-2019:3248</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3197">https://access.redhat.com/errata/RHSA-2019:3197</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3204">https://access.redhat.com/errata/RHSA-2019:3204</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3205">https://access.redhat.com/errata/RHSA-2019:3205</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3209">https://access.redhat.com/errata/RHSA-2019:3209</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3219">https://access.redhat.com/errata/RHSA-2019:3219</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3278">https://access.redhat.com/errata/RHSA-2019:3278</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3694">https://access.redhat.com/errata/RHSA-2019:3694</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3754">https://access.redhat.com/errata/RHSA-2019:3754</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3755">https://access.redhat.com/errata/RHSA-2019:3755</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3895">https://access.redhat.com/errata/RHSA-2019:3895</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3916">https://access.redhat.com/errata/RHSA-2019:3916</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3941">https://access.redhat.com/errata/RHSA-2019:3941</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:4191">https://access.redhat.com/errata/RHSA-2019:4191</a>
          <a href="https://access.redhat.com/errata/RHSA-2020:0388">https://access.redhat.com/errata/RHSA-2020:0388</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-14287">https://access.redhat.com/security/cve/CVE-2019-14287</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-14287.html">https://linux.oracle.com/cve/CVE-2019-14287.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-4822.html">https://linux.oracle.com/errata/ELSA-2019-4822.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2019/10/msg00022.html">https://lists.debian.org/debian-lts-announce/2019/10/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IP7SIOAVLSKJGMTIULX52VQUPTVSC43U/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IP7SIOAVLSKJGMTIULX52VQUPTVSC43U/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NPLAM57TPJQGKQMNG6RHFBLACD6K356N/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NPLAM57TPJQGKQMNG6RHFBLACD6K356N/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TUVAOZBYUHZS56A5FQSCDVGXT7PW7FL2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TUVAOZBYUHZS56A5FQSCDVGXT7PW7FL2/</a>
          <a href="https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287">https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287</a>
          <a href="https://seclists.org/bugtraq/2019/Oct/20">https://seclists.org/bugtraq/2019/Oct/20</a>
          <a href="https://seclists.org/bugtraq/2019/Oct/21">https://seclists.org/bugtraq/2019/Oct/21</a>
          <a href="https://security.gentoo.org/glsa/202003-12">https://security.gentoo.org/glsa/202003-12</a>
          <a href="https://security.netapp.com/advisory/ntap-20191017-0003/">https://security.netapp.com/advisory/ntap-20191017-0003/</a>
          <a href="https://support.f5.com/csp/article/K53746212?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K53746212?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&amp;docId=emr_na-hpesbns03976en_us">https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&amp;docId=emr_na-hpesbns03976en_us</a>
          <a href="https://ubuntu.com/security/notices/USN-4154-1">https://ubuntu.com/security/notices/USN-4154-1</a>
          <a href="https://usn.ubuntu.com/4154-1/">https://usn.ubuntu.com/4154-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4543">https://www.debian.org/security/2019/dsa-4543</a>
          <a href="https://www.openwall.com/lists/oss-security/2019/10/15/2">https://www.openwall.com/lists/oss-security/2019/10/15/2</a>
          <a href="https://www.sudo.ws/alerts/minus_1_uid.html">https://www.sudo.ws/alerts/minus_1_uid.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">sudo</td>
        <td>CVE-2019-18634</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.8.19p1-2.1</td>
        <td>1.8.19p1-2.1+deb9u2</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00029.html">http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00029.html</a>
          <a href="http://packetstormsecurity.com/files/156174/Slackware-Security-Advisory-sudo-Updates.html">http://packetstormsecurity.com/files/156174/Slackware-Security-Advisory-sudo-Updates.html</a>
          <a href="http://packetstormsecurity.com/files/156189/Sudo-1.8.25p-Buffer-Overflow.html">http://packetstormsecurity.com/files/156189/Sudo-1.8.25p-Buffer-Overflow.html</a>
          <a href="http://seclists.org/fulldisclosure/2020/Jan/40">http://seclists.org/fulldisclosure/2020/Jan/40</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/01/30/6">http://www.openwall.com/lists/oss-security/2020/01/30/6</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/01/31/1">http://www.openwall.com/lists/oss-security/2020/01/31/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/02/05/2">http://www.openwall.com/lists/oss-security/2020/02/05/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/02/05/5">http://www.openwall.com/lists/oss-security/2020/02/05/5</a>
          <a href="https://access.redhat.com/errata/RHSA-2020:0487">https://access.redhat.com/errata/RHSA-2020:0487</a>
          <a href="https://access.redhat.com/errata/RHSA-2020:0509">https://access.redhat.com/errata/RHSA-2020:0509</a>
          <a href="https://access.redhat.com/errata/RHSA-2020:0540">https://access.redhat.com/errata/RHSA-2020:0540</a>
          <a href="https://access.redhat.com/errata/RHSA-2020:0726">https://access.redhat.com/errata/RHSA-2020:0726</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-18634">https://access.redhat.com/security/cve/CVE-2019-18634</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18634">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18634</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-18634.html">https://linux.oracle.com/cve/CVE-2019-18634.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-0726.html">https://linux.oracle.com/errata/ELSA-2020-0726.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/02/msg00002.html">https://lists.debian.org/debian-lts-announce/2020/02/msg00002.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I6TKF36KOQUVJNBHSVJFA7BU3CCEYD2F/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I6TKF36KOQUVJNBHSVJFA7BU3CCEYD2F/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IY6DZ7WMDKU4ZDML6MJLDAPG42B5WVUC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IY6DZ7WMDKU4ZDML6MJLDAPG42B5WVUC/</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/2">https://seclists.org/bugtraq/2020/Feb/2</a>
          <a href="https://seclists.org/bugtraq/2020/Feb/3">https://seclists.org/bugtraq/2020/Feb/3</a>
          <a href="https://seclists.org/bugtraq/2020/Jan/44">https://seclists.org/bugtraq/2020/Jan/44</a>
          <a href="https://security.gentoo.org/glsa/202003-12">https://security.gentoo.org/glsa/202003-12</a>
          <a href="https://security.netapp.com/advisory/ntap-20200210-0001/">https://security.netapp.com/advisory/ntap-20200210-0001/</a>
          <a href="https://support.apple.com/kb/HT210919">https://support.apple.com/kb/HT210919</a>
          <a href="https://ubuntu.com/security/notices/USN-4263-1">https://ubuntu.com/security/notices/USN-4263-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4263-2">https://ubuntu.com/security/notices/USN-4263-2</a>
          <a href="https://usn.ubuntu.com/4263-1/">https://usn.ubuntu.com/4263-1/</a>
          <a href="https://usn.ubuntu.com/4263-2/">https://usn.ubuntu.com/4263-2/</a>
          <a href="https://www.debian.org/security/2020/dsa-4614">https://www.debian.org/security/2020/dsa-4614</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/01/30/6">https://www.openwall.com/lists/oss-security/2020/01/30/6</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/01/31/1">https://www.openwall.com/lists/oss-security/2020/01/31/1</a>
          <a href="https://www.sudo.ws/alerts/pwfeedback.html">https://www.sudo.ws/alerts/pwfeedback.html</a>
          <a href="https://www.sudo.ws/security.html">https://www.sudo.ws/security.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">sudo</td>
        <td>CVE-2021-3156</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.8.19p1-2.1</td>
        <td>1.8.19p1-2.1+deb9u3</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/161160/Sudo-Heap-Based-Buffer-Overflow.html">http://packetstormsecurity.com/files/161160/Sudo-Heap-Based-Buffer-Overflow.html</a>
          <a href="http://packetstormsecurity.com/files/161230/Sudo-Buffer-Overflow-Privilege-Escalation.html">http://packetstormsecurity.com/files/161230/Sudo-Buffer-Overflow-Privilege-Escalation.html</a>
          <a href="http://packetstormsecurity.com/files/161270/Sudo-1.9.5p1-Buffer-Overflow-Privilege-Escalation.html">http://packetstormsecurity.com/files/161270/Sudo-1.9.5p1-Buffer-Overflow-Privilege-Escalation.html</a>
          <a href="http://packetstormsecurity.com/files/161293/Sudo-1.8.31p2-1.9.5p1-Buffer-Overflow.html">http://packetstormsecurity.com/files/161293/Sudo-1.8.31p2-1.9.5p1-Buffer-Overflow.html</a>
          <a href="http://seclists.org/fulldisclosure/2021/Feb/42">http://seclists.org/fulldisclosure/2021/Feb/42</a>
          <a href="http://seclists.org/fulldisclosure/2021/Jan/79">http://seclists.org/fulldisclosure/2021/Jan/79</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/01/26/3">http://www.openwall.com/lists/oss-security/2021/01/26/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/01/27/1">http://www.openwall.com/lists/oss-security/2021/01/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/01/27/2">http://www.openwall.com/lists/oss-security/2021/01/27/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/02/15/1">http://www.openwall.com/lists/oss-security/2021/02/15/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/14/2">http://www.openwall.com/lists/oss-security/2021/09/14/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3156">https://access.redhat.com/security/cve/CVE-2021-3156</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10348">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10348</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3156.html">https://linux.oracle.com/cve/CVE-2021-3156.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9169.html">https://linux.oracle.com/errata/ELSA-2021-9169.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/01/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/01/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CALA5FTXIQBRRYUA2ZQNJXB6OQMAXEII/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CALA5FTXIQBRRYUA2ZQNJXB6OQMAXEII/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LHXK6ICO5AYLGFK2TAX5MZKUXTUKWOJY/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LHXK6ICO5AYLGFK2TAX5MZKUXTUKWOJY/</a>
          <a href="https://security.gentoo.org/glsa/202101-33">https://security.gentoo.org/glsa/202101-33</a>
          <a href="https://security.netapp.com/advisory/ntap-20210128-0001/">https://security.netapp.com/advisory/ntap-20210128-0001/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210128-0002/">https://security.netapp.com/advisory/ntap-20210128-0002/</a>
          <a href="https://support.apple.com/kb/HT212177">https://support.apple.com/kb/HT212177</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sudo-privesc-jan2021-qnYQfcM">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sudo-privesc-jan2021-qnYQfcM</a>
          <a href="https://ubuntu.com/security/notices/USN-4705-1">https://ubuntu.com/security/notices/USN-4705-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4705-2">https://ubuntu.com/security/notices/USN-4705-2</a>
          <a href="https://www.beyondtrust.com/blog/entry/security-advisory-privilege-management-for-unix-linux-pmul-basic-and-privilege-management-for-mac-pmm-affected-by-sudo-vulnerability">https://www.beyondtrust.com/blog/entry/security-advisory-privilege-management-for-unix-linux-pmul-basic-and-privilege-management-for-mac-pmm-affected-by-sudo-vulnerability</a>
          <a href="https://www.debian.org/security/2021/dsa-4839">https://www.debian.org/security/2021/dsa-4839</a>
          <a href="https://www.kb.cert.org/vuls/id/794544">https://www.kb.cert.org/vuls/id/794544</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/01/26/3">https://www.openwall.com/lists/oss-security/2021/01/26/3</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt">https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt</a>
          <a href="https://www.sudo.ws/alerts/unescape_overflow.html">https://www.sudo.ws/alerts/unescape_overflow.html</a>
          <a href="https://www.sudo.ws/stable.html#1.9.5p2">https://www.sudo.ws/stable.html#1.9.5p2</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_21_02">https://www.synology.com/security/advisory/Synology_SA_21_02</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">tar</td>
        <td>CVE-2018-20482</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.29b-1.1</td>
        <td>1.29b-1.1+deb9u1</td>
        <td class="links" data-more-links="off">
          <a href="http://git.savannah.gnu.org/cgit/tar.git/commit/?id=c15c42ccd1e2377945fd0414eca1a49294bff454">http://git.savannah.gnu.org/cgit/tar.git/commit/?id=c15c42ccd1e2377945fd0414eca1a49294bff454</a>
          <a href="http://lists.gnu.org/archive/html/bug-tar/2018-12/msg00023.html">http://lists.gnu.org/archive/html/bug-tar/2018-12/msg00023.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html">http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html</a>
          <a href="http://www.securityfocus.com/bid/106354">http://www.securityfocus.com/bid/106354</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-20482">https://access.redhat.com/security/cve/CVE-2018-20482</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20482">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20482</a>
          <a href="https://lists.debian.org/debian-lts-announce/2018/12/msg00023.html">https://lists.debian.org/debian-lts-announce/2018/12/msg00023.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/11/msg00025.html">https://lists.debian.org/debian-lts-announce/2021/11/msg00025.html</a>
          <a href="https://news.ycombinator.com/item?id=18745431">https://news.ycombinator.com/item?id=18745431</a>
          <a href="https://security.gentoo.org/glsa/201903-05">https://security.gentoo.org/glsa/201903-05</a>
          <a href="https://twitter.com/thatcks/status/1076166645708668928">https://twitter.com/thatcks/status/1076166645708668928</a>
          <a href="https://ubuntu.com/security/notices/USN-4692-1">https://ubuntu.com/security/notices/USN-4692-1</a>
          <a href="https://utcc.utoronto.ca/~cks/space/blog/sysadmin/TarFindingTruncateBug">https://utcc.utoronto.ca/~cks/space/blog/sysadmin/TarFindingTruncateBug</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">util-linux</td>
        <td>CVE-2016-2779</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.29.2-1+deb9u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/1">http://www.openwall.com/lists/oss-security/2016/02/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/27/2">http://www.openwall.com/lists/oss-security/2016/02/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2779">https://access.redhat.com/security/cve/CVE-2016-2779</a>
          <a href="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922">https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815922</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">node-pkg</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">handlebars</td>
        <td>CVE-2019-19919</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.3.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2019-19919">https://access.redhat.com/security/cve/CVE-2019-19919</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19919">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19919</a>
          <a href="https://github.com/advisories/GHSA-w457-6q6x-cgp9">https://github.com/advisories/GHSA-w457-6q6x-cgp9</a>
          <a href="https://github.com/wycats/handlebars.js/commit/2078c727c627f25d4a149962f05c1e069beb18bc">https://github.com/wycats/handlebars.js/commit/2078c727c627f25d4a149962f05c1e069beb18bc</a>
          <a href="https://github.com/wycats/handlebars.js/issues/1558">https://github.com/wycats/handlebars.js/issues/1558</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-19919">https://nvd.nist.gov/vuln/detail/CVE-2019-19919</a>
          <a href="https://www.npmjs.com/advisories/1164">https://www.npmjs.com/advisories/1164</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">handlebars</td>
        <td>CVE-2021-23369</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.7.7</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23369">https://access.redhat.com/security/cve/CVE-2021-23369</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23369">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23369</a>
          <a href="https://github.com/advisories/GHSA-f2jv-r9rf-7988">https://github.com/advisories/GHSA-f2jv-r9rf-7988</a>
          <a href="https://github.com/handlebars-lang/handlebars.js/commit/b6d3de7123eebba603e321f04afdbae608e8fea8">https://github.com/handlebars-lang/handlebars.js/commit/b6d3de7123eebba603e321f04afdbae608e8fea8</a>
          <a href="https://github.com/handlebars-lang/handlebars.js/commit/f0589701698268578199be25285b2ebea1c1e427">https://github.com/handlebars-lang/handlebars.js/commit/f0589701698268578199be25285b2ebea1c1e427</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23369">https://nvd.nist.gov/vuln/detail/CVE-2021-23369</a>
          <a href="https://security.netapp.com/advisory/ntap-20210604-0008/">https://security.netapp.com/advisory/ntap-20210604-0008/</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074950">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074950</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074951">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074951</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074952">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074952</a>
          <a href="https://snyk.io/vuln/SNYK-JS-HANDLEBARS-1056767">https://snyk.io/vuln/SNYK-JS-HANDLEBARS-1056767</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">handlebars</td>
        <td>GHSA-2cf5-4w76-r9qv</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.5.2, 3.0.8</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-2cf5-4w76-r9qv">https://github.com/advisories/GHSA-2cf5-4w76-r9qv</a>
          <a href="https://www.npmjs.com/advisories/1316">https://www.npmjs.com/advisories/1316</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">handlebars</td>
        <td>GHSA-g9r4-xpmj-mj65</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.5.3, 3.0.8</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-g9r4-xpmj-mj65">https://github.com/advisories/GHSA-g9r4-xpmj-mj65</a>
          <a href="https://www.npmjs.com/advisories/1325">https://www.npmjs.com/advisories/1325</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">handlebars</td>
        <td>GHSA-q2c6-c6pm-g3gh</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.5.3, 3.0.8</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-q2c6-c6pm-g3gh">https://github.com/advisories/GHSA-q2c6-c6pm-g3gh</a>
          <a href="https://www.npmjs.com/advisories/1324">https://www.npmjs.com/advisories/1324</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">handlebars</td>
        <td>GHSA-q42p-pg8m-cqh6</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.0.12</td>
        <td>3.0.7, 4.0.14, 4.1.2</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-q42p-pg8m-cqh6">https://github.com/advisories/GHSA-q42p-pg8m-cqh6</a>
          <a href="https://github.com/handlebars-lang/handlebars.js/commit/7372d4e9dffc9d70c09671aa28b9392a1577fd86">https://github.com/handlebars-lang/handlebars.js/commit/7372d4e9dffc9d70c09671aa28b9392a1577fd86</a>
          <a href="https://github.com/handlebars-lang/handlebars.js/issues/1495">https://github.com/handlebars-lang/handlebars.js/issues/1495</a>
          <a href="https://snyk.io/vuln/SNYK-JS-HANDLEBARS-173692">https://snyk.io/vuln/SNYK-JS-HANDLEBARS-173692</a>
          <a href="https://www.npmjs.com/advisories/755">https://www.npmjs.com/advisories/755</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">handlebars</td>
        <td>GHSA-f52g-6jhx-586p</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.0.12</td>
        <td>4.4.5</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-f52g-6jhx-586p">https://github.com/advisories/GHSA-f52g-6jhx-586p</a>
          <a href="https://www.npmjs.com/advisories/1300">https://www.npmjs.com/advisories/1300</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">handlebars</td>
        <td>NSWG-ECO-519</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.0.12</td>
        <td>&gt;=4.6.0</td>
        <td class="links" data-more-links="off">
          <a href="https://hackerone.com/reports/726364">https://hackerone.com/reports/726364</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ini</td>
        <td>CVE-2020-7788</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.3.5</td>
        <td>1.3.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-7788">https://access.redhat.com/security/cve/CVE-2020-7788</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7788">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7788</a>
          <a href="https://github.com/advisories/GHSA-qqgx-2p2h-9c37">https://github.com/advisories/GHSA-qqgx-2p2h-9c37</a>
          <a href="https://github.com/npm/ini/commit/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1">https://github.com/npm/ini/commit/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1</a>
          <a href="https://github.com/npm/ini/commit/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1 (v1.3.6)">https://github.com/npm/ini/commit/56d2805e07ccd94e2ba0984ac9240ff02d44b6f1 (v1.3.6)</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-7788.html">https://linux.oracle.com/cve/CVE-2020-7788.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-5171.html">https://linux.oracle.com/errata/ELSA-2021-5171.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/12/msg00032.html">https://lists.debian.org/debian-lts-announce/2020/12/msg00032.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-7788">https://nvd.nist.gov/vuln/detail/CVE-2020-7788</a>
          <a href="https://snyk.io/vuln/SNYK-JS-INI-1048974">https://snyk.io/vuln/SNYK-JS-INI-1048974</a>
          <a href="https://www.npmjs.com/advisories/1589">https://www.npmjs.com/advisories/1589</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">js-yaml</td>
        <td>GHSA-8j8c-7jfh-h6hx</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.12.0</td>
        <td>3.13.1</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-8j8c-7jfh-h6hx">https://github.com/advisories/GHSA-8j8c-7jfh-h6hx</a>
          <a href="https://github.com/nodeca/js-yaml/pull/480">https://github.com/nodeca/js-yaml/pull/480</a>
          <a href="https://www.npmjs.com/advisories/813">https://www.npmjs.com/advisories/813</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">js-yaml</td>
        <td>GHSA-2pr6-76vf-7546</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.12.0</td>
        <td>3.13.0</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-2pr6-76vf-7546">https://github.com/advisories/GHSA-2pr6-76vf-7546</a>
          <a href="https://github.com/nodeca/js-yaml/commit/a567ef3c6e61eb319f0bfc2671d91061afb01235">https://github.com/nodeca/js-yaml/commit/a567ef3c6e61eb319f0bfc2671d91061afb01235</a>
          <a href="https://github.com/nodeca/js-yaml/issues/475">https://github.com/nodeca/js-yaml/issues/475</a>
          <a href="https://snyk.io/vuln/SNYK-JS-JSYAML-173999">https://snyk.io/vuln/SNYK-JS-JSYAML-173999</a>
          <a href="https://www.npmjs.com/advisories/788">https://www.npmjs.com/advisories/788</a>
          <a href="https://www.npmjs.com/advisories/788/versions">https://www.npmjs.com/advisories/788/versions</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">json-schema</td>
        <td>CVE-2021-3918</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">0.2.3</td>
        <td>0.4.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3918">https://access.redhat.com/security/cve/CVE-2021-3918</a>
          <a href="https://github.com/advisories/GHSA-896r-f27r-55mw">https://github.com/advisories/GHSA-896r-f27r-55mw</a>
          <a href="https://github.com/kriszyp/json-schema/commit/22f146111f541d9737e832823699ad3528ca7741">https://github.com/kriszyp/json-schema/commit/22f146111f541d9737e832823699ad3528ca7741</a>
          <a href="https://github.com/kriszyp/json-schema/commit/b62f1da1ff5442f23443d6be6a92d00e65cba93a">https://github.com/kriszyp/json-schema/commit/b62f1da1ff5442f23443d6be6a92d00e65cba93a</a>
          <a href="https://github.com/kriszyp/json-schema/commit/f6f6a3b02d667aa4ba2d5d50cc19208c4462abfa">https://github.com/kriszyp/json-schema/commit/f6f6a3b02d667aa4ba2d5d50cc19208c4462abfa</a>
          <a href="https://huntr.dev/bounties/bb6ccd63-f505-4e3a-b55f-cd2662c261a9">https://huntr.dev/bounties/bb6ccd63-f505-4e3a-b55f-cd2662c261a9</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3918.html">https://linux.oracle.com/cve/CVE-2021-3918.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-5171.html">https://linux.oracle.com/errata/ELSA-2021-5171.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3918">https://nvd.nist.gov/vuln/detail/CVE-2021-3918</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">lodash</td>
        <td>CVE-2019-10744</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">4.17.11</td>
        <td>4.17.12</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2019:3024">https://access.redhat.com/errata/RHSA-2019:3024</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-10744">https://access.redhat.com/security/cve/CVE-2019-10744</a>
          <a href="https://github.com/advisories/GHSA-jf85-cpcp-j695">https://github.com/advisories/GHSA-jf85-cpcp-j695</a>
          <a href="https://github.com/lodash/lodash/pull/4336">https://github.com/lodash/lodash/pull/4336</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-10744">https://nvd.nist.gov/vuln/detail/CVE-2019-10744</a>
          <a href="https://security.netapp.com/advisory/ntap-20191004-0005/">https://security.netapp.com/advisory/ntap-20191004-0005/</a>
          <a href="https://snyk.io/vuln/SNYK-JS-LODASH-450202">https://snyk.io/vuln/SNYK-JS-LODASH-450202</a>
          <a href="https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://www.npmjs.com/advisories/1065">https://www.npmjs.com/advisories/1065</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">lodash</td>
        <td>CVE-2020-8203</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.17.11</td>
        <td>4.17.19</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8203">https://access.redhat.com/security/cve/CVE-2020-8203</a>
          <a href="https://github.com/advisories/GHSA-p6mc-m468-83gw">https://github.com/advisories/GHSA-p6mc-m468-83gw</a>
          <a href="https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12">https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12</a>
          <a href="https://github.com/lodash/lodash/issues/4744">https://github.com/lodash/lodash/issues/4744</a>
          <a href="https://github.com/lodash/lodash/issues/4874">https://github.com/lodash/lodash/issues/4874</a>
          <a href="https://hackerone.com/reports/712065">https://hackerone.com/reports/712065</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8203">https://nvd.nist.gov/vuln/detail/CVE-2020-8203</a>
          <a href="https://security.netapp.com/advisory/ntap-20200724-0006/">https://security.netapp.com/advisory/ntap-20200724-0006/</a>
          <a href="https://www.npmjs.com/advisories/1523">https://www.npmjs.com/advisories/1523</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">lodash</td>
        <td>CVE-2021-23337</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.17.11</td>
        <td>4.17.21</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23337">https://access.redhat.com/security/cve/CVE-2021-23337</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337</a>
          <a href="https://github.com/advisories/GHSA-35jh-r3h4-6jhm">https://github.com/advisories/GHSA-35jh-r3h4-6jhm</a>
          <a href="https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851">https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851</a>
          <a href="https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851">https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851</a>
          <a href="https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c">https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23337">https://nvd.nist.gov/vuln/detail/CVE-2021-23337</a>
          <a href="https://security.netapp.com/advisory/ntap-20210312-0006/">https://security.netapp.com/advisory/ntap-20210312-0006/</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932">https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929</a>
          <a href="https://snyk.io/vuln/SNYK-JS-LODASH-1040724">https://snyk.io/vuln/SNYK-JS-LODASH-1040724</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">lodash</td>
        <td>CVE-2020-28500</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.17.11</td>
        <td>4.17.21</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-28500">https://access.redhat.com/security/cve/CVE-2020-28500</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28500">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28500</a>
          <a href="https://github.com/advisories/GHSA-29mw-wpgm-hmr9">https://github.com/advisories/GHSA-29mw-wpgm-hmr9</a>
          <a href="https://github.com/lodash/lodash/blob/npm/trimEnd.js#L8">https://github.com/lodash/lodash/blob/npm/trimEnd.js#L8</a>
          <a href="https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8">https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8</a>
          <a href="https://github.com/lodash/lodash/pull/5065">https://github.com/lodash/lodash/pull/5065</a>
          <a href="https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7">https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-28500">https://nvd.nist.gov/vuln/detail/CVE-2020-28500</a>
          <a href="https://security.netapp.com/advisory/ntap-20210312-0006/">https://security.netapp.com/advisory/ntap-20210312-0006/</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896">https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893</a>
          <a href="https://snyk.io/vuln/SNYK-JS-LODASH-1018905">https://snyk.io/vuln/SNYK-JS-LODASH-1018905</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">minimist</td>
        <td>CVE-2020-7598</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">0.0.8</td>
        <td>1.2.3, 0.2.1</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-7598">https://access.redhat.com/security/cve/CVE-2020-7598</a>
          <a href="https://github.com/advisories/GHSA-vh95-rmgr-6w4m">https://github.com/advisories/GHSA-vh95-rmgr-6w4m</a>
          <a href="https://github.com/substack/minimist/commit/38a4d1caead72ef99e824bb420a2528eec03d9ab">https://github.com/substack/minimist/commit/38a4d1caead72ef99e824bb420a2528eec03d9ab</a>
          <a href="https://github.com/substack/minimist/commit/4cf1354839cb972e38496d35e12f806eea92c11f#diff-a1e0ee62c91705696ddb71aa30ad4f95">https://github.com/substack/minimist/commit/4cf1354839cb972e38496d35e12f806eea92c11f#diff-a1e0ee62c91705696ddb71aa30ad4f95</a>
          <a href="https://github.com/substack/minimist/commit/63e7ed05aa4b1889ec2f3b196426db4500cbda94">https://github.com/substack/minimist/commit/63e7ed05aa4b1889ec2f3b196426db4500cbda94</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-7598.html">https://linux.oracle.com/cve/CVE-2020-7598.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-2852.html">https://linux.oracle.com/errata/ELSA-2020-2852.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-7598">https://nvd.nist.gov/vuln/detail/CVE-2020-7598</a>
          <a href="https://snyk.io/vuln/SNYK-JS-MINIMIST-559764">https://snyk.io/vuln/SNYK-JS-MINIMIST-559764</a>
          <a href="https://www.npmjs.com/advisories/1179">https://www.npmjs.com/advisories/1179</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">printf</td>
        <td>CVE-2021-23354</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">0.2.5</td>
        <td>0.6.1</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/adaltas/node-printf/commit/a8502e7c9b0b22555696a2d8ef67722086413a68">https://github.com/adaltas/node-printf/commit/a8502e7c9b0b22555696a2d8ef67722086413a68</a>
          <a href="https://github.com/adaltas/node-printf/issues/31">https://github.com/adaltas/node-printf/issues/31</a>
          <a href="https://github.com/adaltas/node-printf/pull/32">https://github.com/adaltas/node-printf/pull/32</a>
          <a href="https://github.com/advisories/GHSA-xfhp-gmh8-r8v2">https://github.com/advisories/GHSA-xfhp-gmh8-r8v2</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23354">https://nvd.nist.gov/vuln/detail/CVE-2021-23354</a>
          <a href="https://snyk.io/vuln/SNYK-JS-PRINTF-1072096">https://snyk.io/vuln/SNYK-JS-PRINTF-1072096</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">underscore</td>
        <td>CVE-2021-23358</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.6.0</td>
        <td>1.12.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23358">https://access.redhat.com/security/cve/CVE-2021-23358</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23358">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23358</a>
          <a href="https://github.com/advisories/GHSA-cf4h-3jhx-xvhq">https://github.com/advisories/GHSA-cf4h-3jhx-xvhq</a>
          <a href="https://github.com/jashkenas/underscore/blob/master/modules/template.js%23L71">https://github.com/jashkenas/underscore/blob/master/modules/template.js%23L71</a>
          <a href="https://github.com/jashkenas/underscore/commit/4c73526d43838ad6ab43a6134728776632adeb66">https://github.com/jashkenas/underscore/commit/4c73526d43838ad6ab43a6134728776632adeb66</a>
          <a href="https://github.com/jashkenas/underscore/pull/2917">https://github.com/jashkenas/underscore/pull/2917</a>
          <a href="https://github.com/jashkenas/underscore/releases/tag/1.12.1">https://github.com/jashkenas/underscore/releases/tag/1.12.1</a>
          <a href="https://lists.apache.org/thread.html/r5df90c46f7000c4aab246e947f62361ecfb849c5a553dcdb0ef545e1@%3Cissues.cordova.apache.org%3E">https://lists.apache.org/thread.html/r5df90c46f7000c4aab246e947f62361ecfb849c5a553dcdb0ef545e1@%3Cissues.cordova.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r770f910653772317b117ab4472b0a32c266ee4abbafda28b8a6f9306@%3Cissues.cordova.apache.org%3E">https://lists.apache.org/thread.html/r770f910653772317b117ab4472b0a32c266ee4abbafda28b8a6f9306@%3Cissues.cordova.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/raae088abdfa4fbd84e1d19d7a7ffe52bf8e426b83e6599ea9a734dba@%3Cissues.cordova.apache.org%3E">https://lists.apache.org/thread.html/raae088abdfa4fbd84e1d19d7a7ffe52bf8e426b83e6599ea9a734dba@%3Cissues.cordova.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbc84926bacd377503a3f5c37b923c1931f9d343754488d94e6f08039@%3Cissues.cordova.apache.org%3E">https://lists.apache.org/thread.html/rbc84926bacd377503a3f5c37b923c1931f9d343754488d94e6f08039@%3Cissues.cordova.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/re69ee408b3983b43e9c4a82a9a17cbbf8681bb91a4b61b46f365aeaf@%3Cissues.cordova.apache.org%3E">https://lists.apache.org/thread.html/re69ee408b3983b43e9c4a82a9a17cbbf8681bb91a4b61b46f365aeaf@%3Cissues.cordova.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00038.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00038.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EOKATXXETD2PF3OR36Q5PD2VSVAR6J5Z/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EOKATXXETD2PF3OR36Q5PD2VSVAR6J5Z/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FGEE7U4Z655A2MK5EW4UQQZ7B64XJWBV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FGEE7U4Z655A2MK5EW4UQQZ7B64XJWBV/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23358">https://nvd.nist.gov/vuln/detail/CVE-2021-23358</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1081504">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1081504</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBJASHKENAS-1081505">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBJASHKENAS-1081505</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1081503">https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1081503</a>
          <a href="https://snyk.io/vuln/SNYK-JS-UNDERSCORE-1080984">https://snyk.io/vuln/SNYK-JS-UNDERSCORE-1080984</a>
          <a href="https://ubuntu.com/security/notices/USN-4913-1">https://ubuntu.com/security/notices/USN-4913-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4913-2">https://ubuntu.com/security/notices/USN-4913-2</a>
          <a href="https://www.debian.org/security/2021/dsa-4883">https://www.debian.org/security/2021/dsa-4883</a>
          <a href="https://www.npmjs.com/package/underscore">https://www.npmjs.com/package/underscore</a>
          <a href="https://www.tenable.com/security/tns-2021-14">https://www.tenable.com/security/tns-2021-14</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">url-parse</td>
        <td>CVE-2021-27515</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.4.3</td>
        <td>1.5.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-27515">https://access.redhat.com/security/cve/CVE-2021-27515</a>
          <a href="https://advisory.checkmarx.net/advisory/CX-2021-4306">https://advisory.checkmarx.net/advisory/CX-2021-4306</a>
          <a href="https://github.com/advisories/GHSA-9m6j-fcg5-2442">https://github.com/advisories/GHSA-9m6j-fcg5-2442</a>
          <a href="https://github.com/unshiftio/url-parse/commit/d1e7e8822f26e8a49794b757123b51386325b2b0">https://github.com/unshiftio/url-parse/commit/d1e7e8822f26e8a49794b757123b51386325b2b0</a>
          <a href="https://github.com/unshiftio/url-parse/compare/1.4.7...1.5.0">https://github.com/unshiftio/url-parse/compare/1.4.7...1.5.0</a>
          <a href="https://github.com/unshiftio/url-parse/pull/197">https://github.com/unshiftio/url-parse/pull/197</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-27515">https://nvd.nist.gov/vuln/detail/CVE-2021-27515</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">url-parse</td>
        <td>CVE-2020-8124</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.3</td>
        <td>1.4.5</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8124">https://access.redhat.com/security/cve/CVE-2020-8124</a>
          <a href="https://github.com/advisories/GHSA-46c4-8wrp-j99v">https://github.com/advisories/GHSA-46c4-8wrp-j99v</a>
          <a href="https://hackerone.com/reports/496293">https://hackerone.com/reports/496293</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8124">https://nvd.nist.gov/vuln/detail/CVE-2020-8124</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">url-parse</td>
        <td>CVE-2021-3664</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.4.3</td>
        <td>1.5.2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3664">https://access.redhat.com/security/cve/CVE-2021-3664</a>
          <a href="https://github.com/advisories/GHSA-hh27-ffr2-f2jc">https://github.com/advisories/GHSA-hh27-ffr2-f2jc</a>
          <a href="https://github.com/unshiftio/url-parse/commit/81ab967889b08112d3356e451bf03e6aa0cbb7e0">https://github.com/unshiftio/url-parse/commit/81ab967889b08112d3356e451bf03e6aa0cbb7e0</a>
          <a href="https://github.com/unshiftio/url-parse/issues/205">https://github.com/unshiftio/url-parse/issues/205</a>
          <a href="https://github.com/unshiftio/url-parse/issues/206">https://github.com/unshiftio/url-parse/issues/206</a>
          <a href="https://huntr.dev/bounties/1625557993985-unshiftio/url-parse">https://huntr.dev/bounties/1625557993985-unshiftio/url-parse</a>
          <a href="https://huntr.dev/bounties/1625557993985-unshiftio/url-parse/">https://huntr.dev/bounties/1625557993985-unshiftio/url-parse/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3664">https://nvd.nist.gov/vuln/detail/CVE-2021-3664</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">ws</td>
        <td>CVE-2021-32640</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.2.2</td>
        <td>5.2.3, 6.2.2, 7.4.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-32640">https://access.redhat.com/security/cve/CVE-2021-32640</a>
          <a href="https://github.com/advisories/GHSA-6fc8-4gx4-v693">https://github.com/advisories/GHSA-6fc8-4gx4-v693</a>
          <a href="https://github.com/websockets/ws/commit/00c425ec77993773d823f018f64a5c44e17023ff">https://github.com/websockets/ws/commit/00c425ec77993773d823f018f64a5c44e17023ff</a>
          <a href="https://github.com/websockets/ws/issues/1895">https://github.com/websockets/ws/issues/1895</a>
          <a href="https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693">https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693</a>
          <a href="https://lists.apache.org/thread.html/rdfa7b6253c4d6271e31566ecd5f30b7ce1b8fb2c89d52b8c4e0f4e30@%3Ccommits.tinkerpop.apache.org%3E">https://lists.apache.org/thread.html/rdfa7b6253c4d6271e31566ecd5f30b7ce1b8fb2c89d52b8c4e0f4e30@%3Ccommits.tinkerpop.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-32640">https://nvd.nist.gov/vuln/detail/CVE-2021-32640</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xmldom</td>
        <td>CVE-2021-32796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">0.1.27</td>
        <td>0.7.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-32796">https://access.redhat.com/security/cve/CVE-2021-32796</a>
          <a href="https://github.com/advisories/GHSA-5fg8-2547-mr8q">https://github.com/advisories/GHSA-5fg8-2547-mr8q</a>
          <a href="https://github.com/xmldom/xmldom/commit/7b4b743917a892d407356e055b296dcd6d107e8b">https://github.com/xmldom/xmldom/commit/7b4b743917a892d407356e055b296dcd6d107e8b</a>
          <a href="https://github.com/xmldom/xmldom/security/advisories/GHSA-5fg8-2547-mr8q">https://github.com/xmldom/xmldom/security/advisories/GHSA-5fg8-2547-mr8q</a>
          <a href="https://mattermost.com/blog/coordinated-disclosure-go-xml-vulnerabilities/">https://mattermost.com/blog/coordinated-disclosure-go-xml-vulnerabilities/</a>
          <a href="https://mattermost.com/blog/securing-xml-implementations-across-the-web/">https://mattermost.com/blog/securing-xml-implementations-across-the-web/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-32796">https://nvd.nist.gov/vuln/detail/CVE-2021-32796</a>
          <a href="https://www.npmjs.com/package/@xmldom/xmldom">https://www.npmjs.com/package/@xmldom/xmldom</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
