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
    <title>docker.io/bitnami/memcached:1.6.9-debian-10-r189 (debian 10.10) - Trivy Report - 2022-01-29T16:24:12.61057101Z</title>
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
    <h1>docker.io/bitnami/memcached:1.6.9-debian-10-r189 (debian 10.10) - Trivy Report - 2022-01-29T16:24:12.610583511Z</h1>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22946</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.64.0-4+deb10u2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://curl.se/docs/CVE-2021-22946.html">https://curl.se/docs/CVE-2021-22946.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946</a>
          <a href="https://hackerone.com/reports/1334111">https://hackerone.com/reports/1334111</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22946.html">https://linux.oracle.com/cve/CVE-2021-22946.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.64.0-4+deb10u2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://curl.se/docs/CVE-2021-22947.html">https://curl.se/docs/CVE-2021-22947.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947</a>
          <a href="https://hackerone.com/reports/1334763">https://hackerone.com/reports/1334763</a>
          <a href="https://launchpad.net/bugs/1944120 (regression bug)">https://launchpad.net/bugs/1944120 (regression bug)</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22947.html">https://linux.oracle.com/cve/CVE-2021-22947.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-3">https://ubuntu.com/security/notices/USN-5079-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-4">https://ubuntu.com/security/notices/USN-5079-4</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gcc-8-base</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">gcc-8-base</td>
        <td>CVE-2019-15847</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html">http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html</a>
          <a href="https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481">https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-15847.html">https://linux.oracle.com/cve/CVE-2019-15847.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1864.html">https://linux.oracle.com/errata/ELSA-2020-1864.html</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
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
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-33574</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33574</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33574.html">https://linux.oracle.com/cve/CVE-2021-33574.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-35942.html">https://linux.oracle.com/cve/CVE-2021-35942.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9560.html">https://linux.oracle.com/errata/ELSA-2021-9560.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libc6</td>
        <td>CVE-2022-23219</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-1751</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1751</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1751.html">https://linux.oracle.com/cve/CVE-2020-1751.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1752</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1752</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-1752.html">https://linux.oracle.com/cve/CVE-2020-1752.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-4444.html">https://linux.oracle.com/errata/ELSA-2020-4444.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/01/28/2">http://www.openwall.com/lists/oss-security/2021/01/28/2</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2146">https://bugs.chromium.org/p/project-zero/issues/detail?id=2146</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3326</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3326.html">https://linux.oracle.com/cve/CVE-2021-3326.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2019-25013</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
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
          <a href="https://security.netapp.com/advisory/ntap-20210205-0004/">https://security.netapp.com/advisory/ntap-20210205-0004/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=24973">https://sourceware.org/bugzilla/show_bug.cgi?id=24973</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b">https://sourceware.org/git/?p=glibc.git;a=commit;h=ee7a3144c9922808181009b7b3e50e852fb4999b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2020-10029</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html">http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00033.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10029</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-10029.html">https://linux.oracle.com/cve/CVE-2020-10029.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-0348.html">https://linux.oracle.com/errata/ELSA-2021-0348.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/23N76M3EDP2GIW4GOIQRYTKRE7PPBRB2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JZTFUD5VH2GU3YOXA2KBQSBIDZRDWNZ3/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU5JJGENOK7K4X5RYAA5PL647C6HD22E/</a>
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
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27618</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27618.html">https://linux.oracle.com/cve/CVE-2020-27618.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9344.html">https://linux.oracle.com/errata/ELSA-2021-9344.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210401-0006/">https://security.netapp.com/advisory/ntap-20210401-0006/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21">https://sourceware.org/bugzilla/show_bug.cgi?id=19519#c21</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=26224">https://sourceware.org/bugzilla/show_bug.cgi?id=26224</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-3998</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.28-10</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3998</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22946</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">7.64.0-4+deb10u2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://curl.se/docs/CVE-2021-22946.html">https://curl.se/docs/CVE-2021-22946.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22946</a>
          <a href="https://hackerone.com/reports/1334111">https://hackerone.com/reports/1334111</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22946.html">https://linux.oracle.com/cve/CVE-2021-22946.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.64.0-4+deb10u2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://curl.se/docs/CVE-2021-22947.html">https://curl.se/docs/CVE-2021-22947.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22947</a>
          <a href="https://hackerone.com/reports/1334763">https://hackerone.com/reports/1334763</a>
          <a href="https://launchpad.net/bugs/1944120 (regression bug)">https://launchpad.net/bugs/1944120 (regression bug)</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22947.html">https://linux.oracle.com/cve/CVE-2021-22947.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4059.html">https://linux.oracle.com/errata/ELSA-2021-4059.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APOAK4X73EJTAPTSVT7IRVDMUWVXNWGD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RWLEC6YVEM2HWUBX67SDGPSY4CQB72OE/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211029-0003/">https://security.netapp.com/advisory/ntap-20211029-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-1">https://ubuntu.com/security/notices/USN-5079-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-2">https://ubuntu.com/security/notices/USN-5079-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-3">https://ubuntu.com/security/notices/USN-5079-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5079-4">https://ubuntu.com/security/notices/USN-5079-4</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgcc1</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgcc1</td>
        <td>CVE-2019-15847</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html">http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html</a>
          <a href="https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481">https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-15847.html">https://linux.oracle.com/cve/CVE-2019-15847.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1864.html">https://linux.oracle.com/errata/ELSA-2020-1864.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2021-33560</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.8.4-5+deb10u1</td>
        <td></td>
        <td class="links" data-more-links="off">
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
          <a href="https://ubuntu.com/security/notices/USN-5080-1">https://ubuntu.com/security/notices/USN-5080-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5080-2">https://ubuntu.com/security/notices/USN-5080-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2019-13627</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.8.4-5+deb10u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html">http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2019/10/02/2">http://www.openwall.com/lists/oss-security/2019/10/02/2</a>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">libgmp10</td>
        <td>CVE-2021-43618</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2:6.1.2+dfsg-4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.debian.org/994405">https://bugs.debian.org/994405</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618</a>
          <a href="https://gmplib.org/list-archives/gmp-bugs/2021-September/005077.html">https://gmplib.org/list-archives/gmp-bugs/2021-September/005077.html</a>
          <a href="https://gmplib.org/repo/gmp-6.2/rev/561a9c25298e">https://gmplib.org/repo/gmp-6.2/rev/561a9c25298e</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00001.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00001.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2021-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u2</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u3</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libidn2-0</td>
        <td>CVE-2019-12290</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.0.5-1+deb10u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00008.html">http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00008.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00009.html">http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00009.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12290">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12290</a>
          <a href="https://gitlab.com/libidn/libidn2/commit/241e8f486134793cb0f4a5b0e5817a97883401f5">https://gitlab.com/libidn/libidn2/commit/241e8f486134793cb0f4a5b0e5817a97883401f5</a>
          <a href="https://gitlab.com/libidn/libidn2/commit/614117ef6e4c60e1950d742e3edf0a0ef8d389de">https://gitlab.com/libidn/libidn2/commit/614117ef6e4c60e1950d742e3edf0a0ef8d389de</a>
          <a href="https://gitlab.com/libidn/libidn2/merge_requests/71">https://gitlab.com/libidn/libidn2/merge_requests/71</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFT76Y7OSGPZV3EBEHD6ISVUM3DLARM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UFT76Y7OSGPZV3EBEHD6ISVUM3DLARM/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KXDKYWFV6N2HHVSE67FFDM7G3FEL2ZNE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KXDKYWFV6N2HHVSE67FFDM7G3FEL2ZNE/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ONG3GJRRJO35COPGVJXXSZLU4J5Y42AT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ONG3GJRRJO35COPGVJXXSZLU4J5Y42AT/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RSI4TI2JTQWQ3YEUX5X36GTVGKO4QKZ5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RSI4TI2JTQWQ3YEUX5X36GTVGKO4QKZ5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U6ZXL2RDNQRAHCMKWPOMJFKYJ344X4HL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U6ZXL2RDNQRAHCMKWPOMJFKYJ344X4HL/</a>
          <a href="https://security.gentoo.org/glsa/202003-63">https://security.gentoo.org/glsa/202003-63</a>
          <a href="https://ubuntu.com/security/notices/USN-4168-1">https://ubuntu.com/security/notices/USN-4168-1</a>
          <a href="https://usn.ubuntu.com/4168-1/">https://usn.ubuntu.com/4168-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2021-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u2</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u3</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2021-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u2</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u3</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2021-36222</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u2</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2021-37750</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.17-3+deb10u1</td>
        <td>1.17-3+deb10u3</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49">https://github.com/krb5/krb5/commit/d775c95af7606a51bf79547a94fa52ddd1cb7f49</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37750.html">https://linux.oracle.com/cve/CVE-2021-37750.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4788.html">https://linux.oracle.com/errata/ELSA-2021-4788.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/09/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MFCLW7D46E4VCREKKH453T5DA4XOLHU2/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210923-0002/">https://security.netapp.com/advisory/ntap-20210923-0002/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libnghttp2-14</td>
        <td>CVE-2020-11080</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.36.0-2+deb10u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html">http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00024.html</a>
          <a href="https://github.com/nghttp2/nghttp2/commit/336a98feb0d56b9ac54e12736b18785c27f75090">https://github.com/nghttp2/nghttp2/commit/336a98feb0d56b9ac54e12736b18785c27f75090</a>
          <a href="https://github.com/nghttp2/nghttp2/commit/f8da73bd042f810f34d19f9eae02b46d870af394">https://github.com/nghttp2/nghttp2/commit/f8da73bd042f810f34d19f9eae02b46d870af394</a>
          <a href="https://github.com/nghttp2/nghttp2/security/advisories/GHSA-q5wr-xfw9-q7xr">https://github.com/nghttp2/nghttp2/security/advisories/GHSA-q5wr-xfw9-q7xr</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-11080.html">https://linux.oracle.com/cve/CVE-2020-11080.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5765.html">https://linux.oracle.com/errata/ELSA-2020-5765.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4OOYAMJVLLCLXDTHW3V5UXNULZBBK4O6/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4OOYAMJVLLCLXDTHW3V5UXNULZBBK4O6/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AAC2AA36OTRHKSVM5OV7TTVB3CZIGEFL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AAC2AA36OTRHKSVM5OV7TTVB3CZIGEFL/</a>
          <a href="https://www.debian.org/security/2020/dsa-4696">https://www.debian.org/security/2020/dsa-4696</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpcre3</td>
        <td>CVE-2020-14155</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.39-12</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2020/Dec/32">http://seclists.org/fulldisclosure/2020/Dec/32</a>
          <a href="http://seclists.org/fulldisclosure/2021/Feb/14">http://seclists.org/fulldisclosure/2021/Feb/14</a>
          <a href="https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/">https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/</a>
          <a href="https://bugs.gentoo.org/717920">https://bugs.gentoo.org/717920</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-14155.html">https://linux.oracle.com/cve/CVE-2020-14155.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4373.html">https://linux.oracle.com/errata/ELSA-2021-4373.html</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://support.apple.com/kb/HT211931">https://support.apple.com/kb/HT211931</a>
          <a href="https://support.apple.com/kb/HT212147">https://support.apple.com/kb/HT212147</a>
          <a href="https://www.pcre.org/original/changelog.txt">https://www.pcre.org/original/changelog.txt</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssh2-1</td>
        <td>CVE-2019-13115</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.8.0-2.1</td>
        <td></td>
        <td class="links" data-more-links="off">
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
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3711</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.1.1d-0+deb10u6</td>
        <td>1.1.1d-0+deb10u7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0010/">https://security.netapp.com/advisory/ntap-20210827-0010/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-1">https://ubuntu.com/security/notices/USN-5051-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4963">https://www.debian.org/security/2021/dsa-4963</a>
          <a href="https://www.openssl.org/news/secadv/20210824.txt">https://www.openssl.org/news/secadv/20210824.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-16">https://www.tenable.com/security/tns-2021-16</a>
          <a href="https://www.tenable.com/security/tns-2022-02">https://www.tenable.com/security/tns-2022-02</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-0+deb10u6</td>
        <td>1.1.1d-0+deb10u7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">libstdc++6</td>
        <td>CVE-2018-12886</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup">https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379&amp;view=markup</a>
          <a href="https://www.gnu.org/software/gcc/gcc-8/changes.html">https://www.gnu.org/software/gcc/gcc-8/changes.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libstdc++6</td>
        <td>CVE-2019-15847</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.3.0-6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html">http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html</a>
          <a href="https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481">https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-15847.html">https://linux.oracle.com/cve/CVE-2019-15847.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1864.html">https://linux.oracle.com/errata/ELSA-2020-1864.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2019-3843</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108116">http://www.securityfocus.com/bid/108116</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843</a>
          <a href="https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)">https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3843.html">https://linux.oracle.com/cve/CVE-2019-3843.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2019-3844</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108096">http://www.securityfocus.com/bid/108096</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3844.html">https://linux.oracle.com/cve/CVE-2019-3844.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2021-33910</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td>241-7~deb10u8</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html">http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/04/2">http://www.openwall.com/lists/oss-security/2021/08/04/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/3">http://www.openwall.com/lists/oss-security/2021/08/17/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/07/3">http://www.openwall.com/lists/oss-security/2021/09/07/3</a>
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
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997</a>
          <a href="https://ubuntu.com/security/notices/USN-5226-1">https://ubuntu.com/security/notices/USN-5226-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/10/2">https://www.openwall.com/lists/oss-security/2022/01/10/2</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2019-3843</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108116">http://www.securityfocus.com/bid/108116</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3843</a>
          <a href="https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)">https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3843.html">https://linux.oracle.com/cve/CVE-2019-3843.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2019-3844</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/108096">http://www.securityfocus.com/bid/108096</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3844</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-3844.html">https://linux.oracle.com/cve/CVE-2019-3844.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-1794.html">https://linux.oracle.com/errata/ELSA-2020-1794.html</a>
          <a href="https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E">https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20190619-0002/">https://security.netapp.com/advisory/ntap-20190619-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4269-1">https://ubuntu.com/security/notices/USN-4269-1</a>
          <a href="https://usn.ubuntu.com/4269-1/">https://usn.ubuntu.com/4269-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2021-33910</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">241-7~deb10u7</td>
        <td>241-7~deb10u8</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html">http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/04/2">http://www.openwall.com/lists/oss-security/2021/08/04/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/3">http://www.openwall.com/lists/oss-security/2021/08/17/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/07/3">http://www.openwall.com/lists/oss-security/2021/09/07/3</a>
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
        <td class="pkg-version">241-7~deb10u7</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3997</a>
          <a href="https://ubuntu.com/security/notices/USN-5226-1">https://ubuntu.com/security/notices/USN-5226-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/10/2">https://www.openwall.com/lists/oss-security/2022/01/10/2</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-3711</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.1.1d-0+deb10u6</td>
        <td>1.1.1d-0+deb10u7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://security.netapp.com/advisory/ntap-20210827-0010/">https://security.netapp.com/advisory/ntap-20210827-0010/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5051-1">https://ubuntu.com/security/notices/USN-5051-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4963">https://www.debian.org/security/2021/dsa-4963</a>
          <a href="https://www.openssl.org/news/secadv/20210824.txt">https://www.openssl.org/news/secadv/20210824.txt</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-16">https://www.tenable.com/security/tns-2021-16</a>
          <a href="https://www.tenable.com/security/tns-2022-02">https://www.tenable.com/security/tns-2022-02</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-0+deb10u6</td>
        <td>1.1.1d-0+deb10u7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-16156</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.28.1-6+deb10u1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html">http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html</a>
          <a href="https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/">https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156</a>
          <a href="https://github.com/andk/cpanpm/commit/b27c51adf0fda25dee84cb72cb2b1bf7d832148c">https://github.com/andk/cpanpm/commit/b27c51adf0fda25dee84cb72cb2b1bf7d832148c</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/</a>
          <a href="https://metacpan.org/pod/distribution/CPAN/scripts/cpan">https://metacpan.org/pod/distribution/CPAN/scripts/cpan</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">gobinary</th></tr>
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
