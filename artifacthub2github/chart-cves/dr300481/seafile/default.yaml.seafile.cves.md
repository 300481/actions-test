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
    <title>docker.io/300481/seafile:8.0.5-20210627 (ubuntu 18.04) - Trivy Report - 2022-01-31 16:01:22.754089669 +0000 UTC m=+6.510569003 </title>
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
    <h1>docker.io/300481/seafile:8.0.5-20210627 (ubuntu 18.04) - Trivy Report - 2022-01-31 16:01:22.754117269 +0000 UTC m=+6.510596503</h1>
    <table>
      <tr class="group-header"><th colspan="6">ubuntu</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">cpp</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.176ubuntu2.3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">cpp-7</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22924</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22924">https://access.redhat.com/security/cve/CVE-2021-22924</a>
          <a href="https://curl.se/docs/CVE-2021-22924.html">https://curl.se/docs/CVE-2021-22924.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924</a>
          <a href="https://hackerone.com/reports/1223565">https://hackerone.com/reports/1223565</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22924.html">https://linux.oracle.com/cve/CVE-2021-22924.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3582.html">https://linux.oracle.com/errata/ELSA-2021-3582.html</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html">https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22924">https://nvd.nist.gov/vuln/detail/CVE-2021-22924</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22925</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Sep/39">http://seclists.org/fulldisclosure/2021/Sep/39</a>
          <a href="http://seclists.org/fulldisclosure/2021/Sep/40">http://seclists.org/fulldisclosure/2021/Sep/40</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-22925">https://access.redhat.com/security/cve/CVE-2021-22925</a>
          <a href="https://curl.se/docs/CVE-2021-22925.html">https://curl.se/docs/CVE-2021-22925.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925</a>
          <a href="https://hackerone.com/reports/1223882">https://hackerone.com/reports/1223882</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22925.html">https://linux.oracle.com/cve/CVE-2021-22925.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4511.html">https://linux.oracle.com/errata/ELSA-2021-4511.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22925">https://nvd.nist.gov/vuln/detail/CVE-2021-22925</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://support.apple.com/kb/HT212804">https://support.apple.com/kb/HT212804</a>
          <a href="https://support.apple.com/kb/HT212805">https://support.apple.com/kb/HT212805</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-2">https://ubuntu.com/security/notices/USN-5021-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">curl</td>
        <td>CVE-2021-22946</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">g++</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.176ubuntu2.3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">g++-7</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">gcc</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.176ubuntu2.3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">gcc-7</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">gcc-7-base</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">gcc-8-base</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">git</td>
        <td>CVE-2021-40330</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1:2.17.1-1ubuntu0.8</td>
        <td>1:2.17.1-1ubuntu0.9</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-40330">https://access.redhat.com/security/cve/CVE-2021-40330</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40330">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40330</a>
          <a href="https://github.com/git/git/commit/a02ea577174ab8ed18f847cf1693f213e0b9c473">https://github.com/git/git/commit/a02ea577174ab8ed18f847cf1693f213e0b9c473</a>
          <a href="https://github.com/git/git/compare/v2.30.0...v2.30.1">https://github.com/git/git/compare/v2.30.0...v2.30.1</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-40330">https://nvd.nist.gov/vuln/detail/CVE-2021-40330</a>
          <a href="https://ubuntu.com/security/notices/USN-5076-1">https://ubuntu.com/security/notices/USN-5076-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">git-man</td>
        <td>CVE-2021-40330</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1:2.17.1-1ubuntu0.8</td>
        <td>1:2.17.1-1ubuntu0.9</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-40330">https://access.redhat.com/security/cve/CVE-2021-40330</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40330">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40330</a>
          <a href="https://github.com/git/git/commit/a02ea577174ab8ed18f847cf1693f213e0b9c473">https://github.com/git/git/commit/a02ea577174ab8ed18f847cf1693f213e0b9c473</a>
          <a href="https://github.com/git/git/compare/v2.30.0...v2.30.1">https://github.com/git/git/compare/v2.30.0...v2.30.1</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-40330">https://nvd.nist.gov/vuln/detail/CVE-2021-40330</a>
          <a href="https://ubuntu.com/security/notices/USN-5076-1">https://ubuntu.com/security/notices/USN-5076-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libapparmor1</td>
        <td>CVE-2016-1585</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.12-4ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://bugs.launchpad.net/apparmor/+bug/1597017">https://bugs.launchpad.net/apparmor/+bug/1597017</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1585">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1585</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-1585">https://nvd.nist.gov/vuln/detail/CVE-2016-1585</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libasan4</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libatomic1</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-dev-bin</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-dev-bin</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-dev-bin</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-dev-bin</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6-dev</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6-dev</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6-dev</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6-dev</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcc1-0</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcilkrts5</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl3-gnutls</td>
        <td>CVE-2021-22924</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22924">https://access.redhat.com/security/cve/CVE-2021-22924</a>
          <a href="https://curl.se/docs/CVE-2021-22924.html">https://curl.se/docs/CVE-2021-22924.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924</a>
          <a href="https://hackerone.com/reports/1223565">https://hackerone.com/reports/1223565</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22924.html">https://linux.oracle.com/cve/CVE-2021-22924.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3582.html">https://linux.oracle.com/errata/ELSA-2021-3582.html</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html">https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22924">https://nvd.nist.gov/vuln/detail/CVE-2021-22924</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl3-gnutls</td>
        <td>CVE-2021-22925</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Sep/39">http://seclists.org/fulldisclosure/2021/Sep/39</a>
          <a href="http://seclists.org/fulldisclosure/2021/Sep/40">http://seclists.org/fulldisclosure/2021/Sep/40</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-22925">https://access.redhat.com/security/cve/CVE-2021-22925</a>
          <a href="https://curl.se/docs/CVE-2021-22925.html">https://curl.se/docs/CVE-2021-22925.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925</a>
          <a href="https://hackerone.com/reports/1223882">https://hackerone.com/reports/1223882</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22925.html">https://linux.oracle.com/cve/CVE-2021-22925.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4511.html">https://linux.oracle.com/errata/ELSA-2021-4511.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22925">https://nvd.nist.gov/vuln/detail/CVE-2021-22925</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://support.apple.com/kb/HT212804">https://support.apple.com/kb/HT212804</a>
          <a href="https://support.apple.com/kb/HT212805">https://support.apple.com/kb/HT212805</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-2">https://ubuntu.com/security/notices/USN-5021-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl3-gnutls</td>
        <td>CVE-2021-22946</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
        <td class="pkg-name">libcurl3-gnutls</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22924</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-22924">https://access.redhat.com/security/cve/CVE-2021-22924</a>
          <a href="https://curl.se/docs/CVE-2021-22924.html">https://curl.se/docs/CVE-2021-22924.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22924</a>
          <a href="https://hackerone.com/reports/1223565">https://hackerone.com/reports/1223565</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22924.html">https://linux.oracle.com/cve/CVE-2021-22924.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3582.html">https://linux.oracle.com/errata/ELSA-2021-3582.html</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html">https://lists.debian.org/debian-lts-announce/2021/08/msg00017.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22924">https://nvd.nist.gov/vuln/detail/CVE-2021-22924</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22925</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.14</td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/fulldisclosure/2021/Sep/39">http://seclists.org/fulldisclosure/2021/Sep/39</a>
          <a href="http://seclists.org/fulldisclosure/2021/Sep/40">http://seclists.org/fulldisclosure/2021/Sep/40</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-22925.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-22925">https://access.redhat.com/security/cve/CVE-2021-22925</a>
          <a href="https://curl.se/docs/CVE-2021-22925.html">https://curl.se/docs/CVE-2021-22925.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22925</a>
          <a href="https://hackerone.com/reports/1223882">https://hackerone.com/reports/1223882</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22925.html">https://linux.oracle.com/cve/CVE-2021-22925.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4511.html">https://linux.oracle.com/errata/ELSA-2021-4511.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FRUCW2UVNYUDZF72DQLFQR4PJEC6CF7V/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22925">https://nvd.nist.gov/vuln/detail/CVE-2021-22925</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0003/">https://security.netapp.com/advisory/ntap-20210902-0003/</a>
          <a href="https://support.apple.com/kb/HT212804">https://support.apple.com/kb/HT212804</a>
          <a href="https://support.apple.com/kb/HT212805">https://support.apple.com/kb/HT212805</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-1">https://ubuntu.com/security/notices/USN-5021-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5021-2">https://ubuntu.com/security/notices/USN-5021-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22946</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
        <td class="pkg-name">libcurl4</td>
        <td>CVE-2021-22947</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.58.0-2ubuntu3.13</td>
        <td>7.58.0-2ubuntu3.15</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libexpat1</td>
        <td>CVE-2022-23852</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.5-3ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23852">https://access.redhat.com/security/cve/CVE-2022-23852</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852</a>
          <a href="https://github.com/libexpat/libexpat/pull/550">https://github.com/libexpat/libexpat/pull/550</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23852">https://nvd.nist.gov/vuln/detail/CVE-2022-23852</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libexpat1</td>
        <td>CVE-2022-23990</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.5-3ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990</a>
          <a href="https://github.com/libexpat/libexpat/pull/551">https://github.com/libexpat/libexpat/pull/551</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libexpat1-dev</td>
        <td>CVE-2022-23852</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.5-3ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23852">https://access.redhat.com/security/cve/CVE-2022-23852</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23852</a>
          <a href="https://github.com/libexpat/libexpat/pull/550">https://github.com/libexpat/libexpat/pull/550</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23852">https://nvd.nist.gov/vuln/detail/CVE-2022-23852</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libexpat1-dev</td>
        <td>CVE-2022-23990</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.5-3ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23990</a>
          <a href="https://github.com/libexpat/libexpat/pull/551">https://github.com/libexpat/libexpat/pull/551</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcc-7-dev</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcc1</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2021-40528</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.8.1-4ubuntu1.2</td>
        <td>1.8.1-4ubuntu1.3</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgd3</td>
        <td>CVE-2021-40145</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.5-4ubuntu0.4</td>
        <td>2.2.5-4ubuntu0.5</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40145">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40145</a>
          <a href="https://github.com/libgd/libgd/commit/c5fd25ce0e48fd5618a972ca9f5e28d6d62006af">https://github.com/libgd/libgd/commit/c5fd25ce0e48fd5618a972ca9f5e28d6d62006af</a>
          <a href="https://github.com/libgd/libgd/issues/700">https://github.com/libgd/libgd/issues/700</a>
          <a href="https://github.com/libgd/libgd/pull/713">https://github.com/libgd/libgd/pull/713</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-40145">https://nvd.nist.gov/vuln/detail/CVE-2021-40145</a>
          <a href="https://ubuntu.com/security/notices/USN-5068-1">https://ubuntu.com/security/notices/USN-5068-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libglib2.0-0</td>
        <td>CVE-2021-3800</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.56.4-0ubuntu0.18.04.8</td>
        <td>2.56.4-0ubuntu0.18.04.9</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3800">https://access.redhat.com/security/cve/CVE-2021-3800</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3800">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3800</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3800.html">https://linux.oracle.com/cve/CVE-2021-3800.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4385.html">https://linux.oracle.com/errata/ELSA-2021-4385.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5189-1">https://ubuntu.com/security/notices/USN-5189-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2017/06/23/8">https://www.openwall.com/lists/oss-security/2017/06/23/8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgomp1</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
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
        <td>CVE-2021-36222</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-36222">https://access.redhat.com/security/cve/CVE-2021-36222</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-36222">https://nvd.nist.gov/vuln/detail/CVE-2021-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libitm1</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
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
        <td>CVE-2021-36222</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-36222">https://access.redhat.com/security/cve/CVE-2021-36222</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-36222">https://nvd.nist.gov/vuln/detail/CVE-2021-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
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
        <td>CVE-2021-36222</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-36222">https://access.redhat.com/security/cve/CVE-2021-36222</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-36222">https://nvd.nist.gov/vuln/detail/CVE-2021-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2018-20217</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
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
        <td>CVE-2021-36222</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.16-2ubuntu0.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-36222">https://access.redhat.com/security/cve/CVE-2021-36222</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36222</a>
          <a href="https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562">https://github.com/krb5/krb5/commit/fc98f520caefff2e5ee9a0026fdf5109944b3562</a>
          <a href="https://github.com/krb5/krb5/releases">https://github.com/krb5/krb5/releases</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-36222.html">https://linux.oracle.com/cve/CVE-2021-36222.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3576.html">https://linux.oracle.com/errata/ELSA-2021-3576.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-36222">https://nvd.nist.gov/vuln/detail/CVE-2021-36222</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211104-0007/">https://security.netapp.com/advisory/ntap-20211104-0007/</a>
          <a href="https://web.mit.edu/kerberos/advisories/">https://web.mit.edu/kerberos/advisories/</a>
          <a href="https://www.debian.org/security/2021/dsa-4944">https://www.debian.org/security/2021/dsa-4944</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">liblsan0</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmpx2</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-2342</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2342">https://access.redhat.com/security/cve/CVE-2021-2342</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2342">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2342</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2342.html">https://linux.oracle.com/cve/CVE-2021-2342.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-2372</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2372">https://access.redhat.com/security/cve/CVE-2021-2372</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2372">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2372</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2372.html">https://linux.oracle.com/cve/CVE-2021-2372.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-2">https://ubuntu.com/security/notices/USN-5022-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-2385</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2385">https://access.redhat.com/security/cve/CVE-2021-2385</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2385">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2385</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2385.html">https://linux.oracle.com/cve/CVE-2021-2385.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-2389</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2389">https://access.redhat.com/security/cve/CVE-2021-2389</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2389">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2389</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2389.html">https://linux.oracle.com/cve/CVE-2021-2389.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-2">https://ubuntu.com/security/notices/USN-5022-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
          <a href="https://www.zerodayinitiative.com/advisories/ZDI-21-880/">https://www.zerodayinitiative.com/advisories/ZDI-21-880/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-2390</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2390">https://access.redhat.com/security/cve/CVE-2021-2390</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2390">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2390</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2390.html">https://linux.oracle.com/cve/CVE-2021-2390.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
          <a href="https://www.zerodayinitiative.com/advisories/ZDI-21-881/">https://www.zerodayinitiative.com/advisories/ZDI-21-881/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-35604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.36-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-35604">https://access.redhat.com/security/cve/CVE-2021-35604</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5MLAXYFLUDC636S46X34USCLDZAOFBM2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5MLAXYFLUDC636S46X34USCLDZAOFBM2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PRCU3RTIPVKPC3GMC76YW7DJEXUEY6FG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PRCU3RTIPVKPC3GMC76YW7DJEXUEY6FG/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XF3ZFPL3JJ26YRUGXLXQZYJBLZV3WC2C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XF3ZFPL3JJ26YRUGXLXQZYJBLZV3WC2C/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-1">https://ubuntu.com/security/notices/USN-5123-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-2">https://ubuntu.com/security/notices/USN-5123-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5170-1">https://ubuntu.com/security/notices/USN-5170-1</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-35624</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.36-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-35624">https://access.redhat.com/security/cve/CVE-2021-35624</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35624">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35624</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35624">https://nvd.nist.gov/vuln/detail/CVE-2021-35624</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-1">https://ubuntu.com/security/notices/USN-5123-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-2">https://ubuntu.com/security/notices/USN-5123-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2021-46322</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46322">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46322</a>
          <a href="https://github.com/svaarala/duktape/issues/2448">https://github.com/svaarala/duktape/issues/2448</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21245</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21245">https://access.redhat.com/security/cve/CVE-2022-21245</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21245">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21245</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21245">https://nvd.nist.gov/vuln/detail/CVE-2022-21245</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21270</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21270">https://access.redhat.com/security/cve/CVE-2022-21270</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21270">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21270</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21270">https://nvd.nist.gov/vuln/detail/CVE-2022-21270</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21303</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21303">https://access.redhat.com/security/cve/CVE-2022-21303</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21303">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21303</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21303">https://nvd.nist.gov/vuln/detail/CVE-2022-21303</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21304</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21304">https://access.redhat.com/security/cve/CVE-2022-21304</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21304">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21304</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21304">https://nvd.nist.gov/vuln/detail/CVE-2022-21304</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21344</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21344">https://access.redhat.com/security/cve/CVE-2022-21344</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21344">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21344</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21344">https://nvd.nist.gov/vuln/detail/CVE-2022-21344</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient-dev</td>
        <td>CVE-2022-21367</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21367">https://access.redhat.com/security/cve/CVE-2022-21367</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21367">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21367</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21367">https://nvd.nist.gov/vuln/detail/CVE-2022-21367</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-2342</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2342">https://access.redhat.com/security/cve/CVE-2021-2342</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2342">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2342</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2342.html">https://linux.oracle.com/cve/CVE-2021-2342.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-2372</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2372">https://access.redhat.com/security/cve/CVE-2021-2372</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2372">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2372</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2372.html">https://linux.oracle.com/cve/CVE-2021-2372.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-2">https://ubuntu.com/security/notices/USN-5022-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-2385</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2385">https://access.redhat.com/security/cve/CVE-2021-2385</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2385">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2385</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2385.html">https://linux.oracle.com/cve/CVE-2021-2385.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6OO2Q5PIFURXLLKCIJE6XF6VL4LLMNO5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-2389</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2389">https://access.redhat.com/security/cve/CVE-2021-2389</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2389">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2389</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2389.html">https://linux.oracle.com/cve/CVE-2021-2389.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-2">https://ubuntu.com/security/notices/USN-5022-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
          <a href="https://www.zerodayinitiative.com/advisories/ZDI-21-880/">https://www.zerodayinitiative.com/advisories/ZDI-21-880/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-2390</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.35-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-2390">https://access.redhat.com/security/cve/CVE-2021-2390</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2390">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2390</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-2390.html">https://linux.oracle.com/cve/CVE-2021-2390.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3590.html">https://linux.oracle.com/errata/ELSA-2021-3590.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210723-0001/">https://security.netapp.com/advisory/ntap-20210723-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-1">https://ubuntu.com/security/notices/USN-5022-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5022-3">https://ubuntu.com/security/notices/USN-5022-3</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2021.html">https://www.oracle.com/security-alerts/cpujul2021.html</a>
          <a href="https://www.zerodayinitiative.com/advisories/ZDI-21-881/">https://www.zerodayinitiative.com/advisories/ZDI-21-881/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-35604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.36-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-35604">https://access.redhat.com/security/cve/CVE-2021-35604</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UTW5KMPPDKIMGB4ULE2HS22HYLVKYIH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5MLAXYFLUDC636S46X34USCLDZAOFBM2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5MLAXYFLUDC636S46X34USCLDZAOFBM2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PRCU3RTIPVKPC3GMC76YW7DJEXUEY6FG/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PRCU3RTIPVKPC3GMC76YW7DJEXUEY6FG/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VGR5ZTB5QEDRRC6G5U6TFNCIVBBKGS5J/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XF3ZFPL3JJ26YRUGXLXQZYJBLZV3WC2C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XF3ZFPL3JJ26YRUGXLXQZYJBLZV3WC2C/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-1">https://ubuntu.com/security/notices/USN-5123-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-2">https://ubuntu.com/security/notices/USN-5123-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5170-1">https://ubuntu.com/security/notices/USN-5170-1</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-35624</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td>5.7.36-0ubuntu0.18.04.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-35624">https://access.redhat.com/security/cve/CVE-2021-35624</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35624">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35624</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35624">https://nvd.nist.gov/vuln/detail/CVE-2021-35624</a>
          <a href="https://security.netapp.com/advisory/ntap-20211022-0003/">https://security.netapp.com/advisory/ntap-20211022-0003/</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-1">https://ubuntu.com/security/notices/USN-5123-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5123-2">https://ubuntu.com/security/notices/USN-5123-2</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2021-46322</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46322">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-46322</a>
          <a href="https://github.com/svaarala/duktape/issues/2448">https://github.com/svaarala/duktape/issues/2448</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21245</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21245">https://access.redhat.com/security/cve/CVE-2022-21245</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21245">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21245</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21245">https://nvd.nist.gov/vuln/detail/CVE-2022-21245</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21270</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21270">https://access.redhat.com/security/cve/CVE-2022-21270</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21270">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21270</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21270">https://nvd.nist.gov/vuln/detail/CVE-2022-21270</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21303</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21303">https://access.redhat.com/security/cve/CVE-2022-21303</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21303">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21303</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21303">https://nvd.nist.gov/vuln/detail/CVE-2022-21303</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21304</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21304">https://access.redhat.com/security/cve/CVE-2022-21304</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21304">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21304</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21304">https://nvd.nist.gov/vuln/detail/CVE-2022-21304</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21344</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21344">https://access.redhat.com/security/cve/CVE-2022-21344</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21344">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21344</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21344">https://nvd.nist.gov/vuln/detail/CVE-2022-21344</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libmysqlclient20</td>
        <td>CVE-2022-21367</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.7.34-0ubuntu0.18.04.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-21367">https://access.redhat.com/security/cve/CVE-2022-21367</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21367">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21367</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-21367">https://nvd.nist.gov/vuln/detail/CVE-2022-21367</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0008/">https://security.netapp.com/advisory/ntap-20220121-0008/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2022.html">https://www.oracle.com/security-alerts/cpujan2022.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnghttp2-14</td>
        <td>CVE-2019-9511</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.30.0-1ubuntu1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00031.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00031.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00032.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00032.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00035.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00035.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00003.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00003.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00005.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00005.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00014.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00014.html</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2692">https://access.redhat.com/errata/RHSA-2019:2692</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2745">https://access.redhat.com/errata/RHSA-2019:2745</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2746">https://access.redhat.com/errata/RHSA-2019:2746</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2775">https://access.redhat.com/errata/RHSA-2019:2775</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2799">https://access.redhat.com/errata/RHSA-2019:2799</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2925">https://access.redhat.com/errata/RHSA-2019:2925</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2939">https://access.redhat.com/errata/RHSA-2019:2939</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2949">https://access.redhat.com/errata/RHSA-2019:2949</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2955">https://access.redhat.com/errata/RHSA-2019:2955</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2966">https://access.redhat.com/errata/RHSA-2019:2966</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3041">https://access.redhat.com/errata/RHSA-2019:3041</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3932">https://access.redhat.com/errata/RHSA-2019:3932</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3933">https://access.redhat.com/errata/RHSA-2019:3933</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3935">https://access.redhat.com/errata/RHSA-2019:3935</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:4018">https://access.redhat.com/errata/RHSA-2019:4018</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:4019">https://access.redhat.com/errata/RHSA-2019:4019</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:4020">https://access.redhat.com/errata/RHSA-2019:4020</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:4021">https://access.redhat.com/errata/RHSA-2019:4021</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9511">https://access.redhat.com/security/cve/CVE-2019-9511</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9511">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9511</a>
          <a href="https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md">https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md</a>
          <a href="https://kb.cert.org/vuls/id/605641/">https://kb.cert.org/vuls/id/605641/</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10296">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10296</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9511.html">https://linux.oracle.com/cve/CVE-2019-9511.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2020-5862.html">https://linux.oracle.com/errata/ELSA-2020-5862.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BP556LEG3WENHZI5TAQ6ZEBFTJB4E2IS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BP556LEG3WENHZI5TAQ6ZEBFTJB4E2IS/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JUBYAF6ED3O4XCHQ5C2HYENJLXYXZC4M/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JUBYAF6ED3O4XCHQ5C2HYENJLXYXZC4M/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZLUYPYY3RX4ZJDWZRJIKSULYRJ4PXW7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZLUYPYY3RX4ZJDWZRJIKSULYRJ4PXW7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/POPAEC4FWL4UU4LDEGPY5NPALU24FFQD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/POPAEC4FWL4UU4LDEGPY5NPALU24FFQD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TAZZEVTCN2B4WT6AIBJ7XGYJMBTORJU5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TAZZEVTCN2B4WT6AIBJ7XGYJMBTORJU5/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XHTKU7YQ5EEP2XNSAV4M4VJ7QCBOJMOD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XHTKU7YQ5EEP2XNSAV4M4VJ7QCBOJMOD/</a>
          <a href="https://nodejs.org/en/blog/vulnerability/aug-2019-security-releases/">https://nodejs.org/en/blog/vulnerability/aug-2019-security-releases/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9511">https://nvd.nist.gov/vuln/detail/CVE-2019-9511</a>
          <a href="https://seclists.org/bugtraq/2019/Aug/40">https://seclists.org/bugtraq/2019/Aug/40</a>
          <a href="https://seclists.org/bugtraq/2019/Sep/1">https://seclists.org/bugtraq/2019/Sep/1</a>
          <a href="https://security.netapp.com/advisory/ntap-20190823-0002/">https://security.netapp.com/advisory/ntap-20190823-0002/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190823-0005/">https://security.netapp.com/advisory/ntap-20190823-0005/</a>
          <a href="https://support.f5.com/csp/article/K02591030">https://support.f5.com/csp/article/K02591030</a>
          <a href="https://support.f5.com/csp/article/K02591030?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K02591030?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4099-1">https://ubuntu.com/security/notices/USN-4099-1</a>
          <a href="https://usn.ubuntu.com/4099-1/">https://usn.ubuntu.com/4099-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4505">https://www.debian.org/security/2019/dsa-4505</a>
          <a href="https://www.debian.org/security/2019/dsa-4511">https://www.debian.org/security/2019/dsa-4511</a>
          <a href="https://www.debian.org/security/2020/dsa-4669">https://www.debian.org/security/2020/dsa-4669</a>
          <a href="https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/">https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html">https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_19_33">https://www.synology.com/security/advisory/Synology_SA_19_33</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnghttp2-14</td>
        <td>CVE-2019-9513</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.30.0-1ubuntu1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00031.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00031.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00032.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00032.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00035.html">http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00035.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00003.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00003.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00005.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00005.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00014.html">http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00014.html</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2692">https://access.redhat.com/errata/RHSA-2019:2692</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2745">https://access.redhat.com/errata/RHSA-2019:2745</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2746">https://access.redhat.com/errata/RHSA-2019:2746</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2775">https://access.redhat.com/errata/RHSA-2019:2775</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2799">https://access.redhat.com/errata/RHSA-2019:2799</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2925">https://access.redhat.com/errata/RHSA-2019:2925</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2939">https://access.redhat.com/errata/RHSA-2019:2939</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2949">https://access.redhat.com/errata/RHSA-2019:2949</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2955">https://access.redhat.com/errata/RHSA-2019:2955</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:2966">https://access.redhat.com/errata/RHSA-2019:2966</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3041">https://access.redhat.com/errata/RHSA-2019:3041</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3932">https://access.redhat.com/errata/RHSA-2019:3932</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3933">https://access.redhat.com/errata/RHSA-2019:3933</a>
          <a href="https://access.redhat.com/errata/RHSA-2019:3935">https://access.redhat.com/errata/RHSA-2019:3935</a>
          <a href="https://access.redhat.com/security/cve/CVE-2019-9513">https://access.redhat.com/security/cve/CVE-2019-9513</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513</a>
          <a href="https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md">https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md</a>
          <a href="https://kb.cert.org/vuls/id/605641/">https://kb.cert.org/vuls/id/605641/</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10296">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10296</a>
          <a href="https://linux.oracle.com/cve/CVE-2019-9513.html">https://linux.oracle.com/cve/CVE-2019-9513.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2019-2925.html">https://linux.oracle.com/errata/ELSA-2019-2925.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4ZQGHE3WTYLYAYJEIDJVF2FIGQTAYPMC/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4ZQGHE3WTYLYAYJEIDJVF2FIGQTAYPMC/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CMNFX5MNYRWWIMO4BTKYQCGUDMHO3AXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CMNFX5MNYRWWIMO4BTKYQCGUDMHO3AXP/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JUBYAF6ED3O4XCHQ5C2HYENJLXYXZC4M/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JUBYAF6ED3O4XCHQ5C2HYENJLXYXZC4M/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZLUYPYY3RX4ZJDWZRJIKSULYRJ4PXW7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZLUYPYY3RX4ZJDWZRJIKSULYRJ4PXW7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/POPAEC4FWL4UU4LDEGPY5NPALU24FFQD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/POPAEC4FWL4UU4LDEGPY5NPALU24FFQD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TAZZEVTCN2B4WT6AIBJ7XGYJMBTORJU5/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TAZZEVTCN2B4WT6AIBJ7XGYJMBTORJU5/</a>
          <a href="https://nghttp2.org/blog/2019/08/19/nghttp2-v1-39-2/">https://nghttp2.org/blog/2019/08/19/nghttp2-v1-39-2/</a>
          <a href="https://nodejs.org/en/blog/vulnerability/aug-2019-security-releases/">https://nodejs.org/en/blog/vulnerability/aug-2019-security-releases/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-9513">https://nvd.nist.gov/vuln/detail/CVE-2019-9513</a>
          <a href="https://seclists.org/bugtraq/2019/Aug/40">https://seclists.org/bugtraq/2019/Aug/40</a>
          <a href="https://seclists.org/bugtraq/2019/Sep/1">https://seclists.org/bugtraq/2019/Sep/1</a>
          <a href="https://security.netapp.com/advisory/ntap-20190823-0002/">https://security.netapp.com/advisory/ntap-20190823-0002/</a>
          <a href="https://security.netapp.com/advisory/ntap-20190823-0005/">https://security.netapp.com/advisory/ntap-20190823-0005/</a>
          <a href="https://support.f5.com/csp/article/K02591030">https://support.f5.com/csp/article/K02591030</a>
          <a href="https://support.f5.com/csp/article/K02591030?utm_source=f5support&amp;amp;utm_medium=RSS">https://support.f5.com/csp/article/K02591030?utm_source=f5support&amp;amp;utm_medium=RSS</a>
          <a href="https://ubuntu.com/security/notices/USN-4099-1">https://ubuntu.com/security/notices/USN-4099-1</a>
          <a href="https://usn.ubuntu.com/4099-1/">https://usn.ubuntu.com/4099-1/</a>
          <a href="https://www.debian.org/security/2019/dsa-4505">https://www.debian.org/security/2019/dsa-4505</a>
          <a href="https://www.debian.org/security/2019/dsa-4511">https://www.debian.org/security/2019/dsa-4511</a>
          <a href="https://www.debian.org/security/2020/dsa-4669">https://www.debian.org/security/2020/dsa-4669</a>
          <a href="https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/">https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_19_33">https://www.synology.com/security/advisory/Synology_SA_19_33</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnginx-mod-http-geoip</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnginx-mod-http-image-filter</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnginx-mod-http-xslt-filter</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnginx-mod-mail</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libnginx-mod-stream</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libperl5.26</td>
        <td>CVE-2020-16156</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.26.1-6ubuntu0.5</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-dev</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-dev</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-dev</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-minimal</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-minimal</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-minimal</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-stdlib</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-stdlib</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpython3.6-stdlib</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libquadmath0</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libsqlite3-0</td>
        <td>CVE-2020-9794</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.22.0-1ubuntu0.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9794">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9794</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E</a>
          <a href="https://support.apple.com/HT211168">https://support.apple.com/HT211168</a>
          <a href="https://support.apple.com/HT211170">https://support.apple.com/HT211170</a>
          <a href="https://support.apple.com/HT211171">https://support.apple.com/HT211171</a>
          <a href="https://support.apple.com/HT211175">https://support.apple.com/HT211175</a>
          <a href="https://support.apple.com/HT211178">https://support.apple.com/HT211178</a>
          <a href="https://support.apple.com/HT211179">https://support.apple.com/HT211179</a>
          <a href="https://support.apple.com/HT211181">https://support.apple.com/HT211181</a>
          <a href="https://vuldb.com/?id.155768">https://vuldb.com/?id.155768</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl-dev</td>
        <td>CVE-2021-3711</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3711">https://access.redhat.com/security/cve/CVE-2021-3711</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3711">https://nvd.nist.gov/vuln/detail/CVE-2021-3711</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0097.html">https://rustsec.org/advisories/RUSTSEC-2021-0097.html</a>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl-dev</td>
        <td>CVE-2021-3712</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
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
        <td class="pkg-name">libssl1.0.0</td>
        <td>CVE-2021-3712</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.0.2n-1ubuntu5.6</td>
        <td>1.0.2n-1ubuntu5.7</td>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3711</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3711">https://access.redhat.com/security/cve/CVE-2021-3711</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3711">https://nvd.nist.gov/vuln/detail/CVE-2021-3711</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0097.html">https://rustsec.org/advisories/RUSTSEC-2021-0097.html</a>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3712</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
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
        <td class="pkg-name">libstdc++-7-dev</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libstdc++6</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libsystemd0</td>
        <td>CVE-2021-33910</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">237-3ubuntu10.48</td>
        <td>237-3ubuntu10.49</td>
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
        <td class="pkg-name">libtsan0</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">8.4.0-1ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libubsan0</td>
        <td>CVE-2020-13844</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">7.5.0-3ubuntu1~18.04</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html">http://lists.llvm.org/pipermail/llvm-dev/2020-June/142109.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00039.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html">http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00040.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-13844">https://access.redhat.com/security/cve/CVE-2020-13844</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13844</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/downloads/straight-line-speculation</a>
          <a href="https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions">https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/frequently-asked-questions</a>
          <a href="https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html">https://gcc.gnu.org/pipermail/gcc-patches/2020-June/547520.html</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=679db70801da9fda91d26caf13bf5b5ccc74e8e8</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libudev1</td>
        <td>CVE-2021-33910</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">237-3ubuntu10.48</td>
        <td>237-3ubuntu10.49</td>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-33909</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html">http://packetstormsecurity.com/files/163621/Sequoia-A-Deep-Root-In-Linuxs-Filesystem-Layer.html</a>
          <a href="http://packetstormsecurity.com/files/163671/Kernel-Live-Patch-Security-Notice-LSN-0079-1.html">http://packetstormsecurity.com/files/163671/Kernel-Live-Patch-Security-Notice-LSN-0079-1.html</a>
          <a href="http://packetstormsecurity.com/files/164155/Kernel-Live-Patch-Security-Notice-LSN-0081-1.html">http://packetstormsecurity.com/files/164155/Kernel-Live-Patch-Security-Notice-LSN-0081-1.html</a>
          <a href="http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html">http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/07/22/7">http://www.openwall.com/lists/oss-security/2021/07/22/7</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/25/10">http://www.openwall.com/lists/oss-security/2021/08/25/10</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/17/2">http://www.openwall.com/lists/oss-security/2021/09/17/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/17/4">http://www.openwall.com/lists/oss-security/2021/09/17/4</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/09/21/1">http://www.openwall.com/lists/oss-security/2021/09/21/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-33909">https://access.redhat.com/security/cve/CVE-2021-33909</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33909">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33909</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8cae8cd89f05f6de223d63e6d15e31c8ba9cf53b">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8cae8cd89f05f6de223d63e6d15e31c8ba9cf53b</a>
          <a href="https://github.com/torvalds/linux/commit/8cae8cd89f05f6de223d63e6d15e31c8ba9cf53b">https://github.com/torvalds/linux/commit/8cae8cd89f05f6de223d63e6d15e31c8ba9cf53b</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33909.html">https://linux.oracle.com/cve/CVE-2021-33909.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9410.html">https://linux.oracle.com/errata/ELSA-2021-9410.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2021/07/msg00014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/07/msg00015.html">https://lists.debian.org/debian-lts-announce/2021/07/msg00015.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/07/msg00016.html">https://lists.debian.org/debian-lts-announce/2021/07/msg00016.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z4UHHIGISO3FVRF4CQNJS4IKA25ATSFU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z4UHHIGISO3FVRF4CQNJS4IKA25ATSFU/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33909">https://nvd.nist.gov/vuln/detail/CVE-2021-33909</a>
          <a href="https://security.netapp.com/advisory/ntap-20210819-0004/">https://security.netapp.com/advisory/ntap-20210819-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-5014-1">https://ubuntu.com/security/notices/USN-5014-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5015-1">https://ubuntu.com/security/notices/USN-5015-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5016-1">https://ubuntu.com/security/notices/USN-5016-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5017-1">https://ubuntu.com/security/notices/USN-5017-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4941">https://www.debian.org/security/2021/dsa-4941</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/07/20/1">https://www.openwall.com/lists/oss-security/2021/07/20/1</a>
          <a href="https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt">https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3653</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html">http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3653">https://access.redhat.com/security/cve/CVE-2021-3653</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1983686">https://bugzilla.redhat.com/show_bug.cgi?id=1983686</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3653">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3653</a>
          <a href="https://github.com/torvalds/linux/commit/3d6368ef580a">https://github.com/torvalds/linux/commit/3d6368ef580a</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3653.html">https://linux.oracle.com/cve/CVE-2021-3653.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9565.html">https://linux.oracle.com/errata/ELSA-2021-9565.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3653">https://nvd.nist.gov/vuln/detail/CVE-2021-3653</a>
          <a href="https://ubuntu.com/security/notices/USN-5062-1">https://ubuntu.com/security/notices/USN-5062-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-1">https://ubuntu.com/security/notices/USN-5071-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-2">https://ubuntu.com/security/notices/USN-5071-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5072-1">https://ubuntu.com/security/notices/USN-5072-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-1">https://ubuntu.com/security/notices/USN-5073-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-2">https://ubuntu.com/security/notices/USN-5073-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5082-1">https://ubuntu.com/security/notices/USN-5082-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/08/16/1">https://www.openwall.com/lists/oss-security/2021/08/16/1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3656</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3656">https://access.redhat.com/security/cve/CVE-2021-3656</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3656">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3656</a>
          <a href="https://github.com/torvalds/linux/commit/89c8a4984fc9">https://github.com/torvalds/linux/commit/89c8a4984fc9</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3656.html">https://linux.oracle.com/cve/CVE-2021-3656.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9565.html">https://linux.oracle.com/errata/ELSA-2021-9565.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-1">https://ubuntu.com/security/notices/USN-5071-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-2">https://ubuntu.com/security/notices/USN-5071-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5072-1">https://ubuntu.com/security/notices/USN-5072-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-1">https://ubuntu.com/security/notices/USN-5073-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-2">https://ubuntu.com/security/notices/USN-5073-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5082-1">https://ubuntu.com/security/notices/USN-5082-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/08/16/1">https://www.openwall.com/lists/oss-security/2021/08/16/1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4002</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4002">https://access.redhat.com/security/cve/CVE-2021-4002</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4002">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4002</a>
          <a href="https://git.kernel.org/linus/a4a118f2eead1d6c49e00765de89878288d4b890">https://git.kernel.org/linus/a4a118f2eead1d6c49e00765de89878288d4b890</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=13e4ad2ce8df6e058ef482a31fdd81c725b0f7ea">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=13e4ad2ce8df6e058ef482a31fdd81c725b0f7ea</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a4a118f2eead1d6c49e00765de89878288d4b890">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a4a118f2eead1d6c49e00765de89878288d4b890</a>
          <a href="https://ubuntu.com/security/notices/USN-5206-1">https://ubuntu.com/security/notices/USN-5206-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5207-1">https://ubuntu.com/security/notices/USN-5207-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5208-1">https://ubuntu.com/security/notices/USN-5208-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5209-1">https://ubuntu.com/security/notices/USN-5209-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5210-1">https://ubuntu.com/security/notices/USN-5210-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5211-1">https://ubuntu.com/security/notices/USN-5211-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5218-1">https://ubuntu.com/security/notices/USN-5218-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/11/25/1">https://www.openwall.com/lists/oss-security/2021/11/25/1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2013-7445</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2013-7445">https://access.redhat.com/security/cve/CVE-2013-7445</a>
          <a href="https://bugzilla.kernel.org/show_bug.cgi?id=60533">https://bugzilla.kernel.org/show_bug.cgi?id=60533</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-7445">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-7445</a>
          <a href="https://lists.freedesktop.org/archives/dri-devel/2015-September/089778.html (potential start towards fixing)">https://lists.freedesktop.org/archives/dri-devel/2015-September/089778.html (potential start towards fixing)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2015-8553</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://thread.gmane.org/gmane.linux.kernel/1924087/focus=1930758 (regression mention)">http://thread.gmane.org/gmane.linux.kernel/1924087/focus=1930758 (regression mention)</a>
          <a href="http://xenbits.xen.org/xsa/advisory-120.html">http://xenbits.xen.org/xsa/advisory-120.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2015-8553">https://access.redhat.com/security/cve/CVE-2015-8553</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8553">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8553</a>
          <a href="https://seclists.org/bugtraq/2019/Aug/18">https://seclists.org/bugtraq/2019/Aug/18</a>
          <a href="https://www.debian.org/security/2019/dsa-4497">https://www.debian.org/security/2019/dsa-4497</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2016-8660</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2016/10/13/8">http://www.openwall.com/lists/oss-security/2016/10/13/8</a>
          <a href="http://www.securityfocus.com/bid/93558">http://www.securityfocus.com/bid/93558</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-8660">https://access.redhat.com/security/cve/CVE-2016-8660</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1384851">https://bugzilla.redhat.com/show_bug.cgi?id=1384851</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8660">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8660</a>
          <a href="https://lore.kernel.org/linux-xfs/895314622.769515.1476375930648.JavaMail.zimbra@redhat.com/">https://lore.kernel.org/linux-xfs/895314622.769515.1476375930648.JavaMail.zimbra@redhat.com/</a>
          <a href="https://marc.info/?l=linux-fsdevel&amp;m=147639177409294&amp;w=2">https://marc.info/?l=linux-fsdevel&amp;m=147639177409294&amp;w=2</a>
          <a href="https://marc.info/?l=linux-xfs&amp;m=149498118228320&amp;w=2">https://marc.info/?l=linux-xfs&amp;m=149498118228320&amp;w=2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2018-17977</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.securityfocus.com/bid/105539">http://www.securityfocus.com/bid/105539</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-17977">https://access.redhat.com/security/cve/CVE-2018-17977</a>
          <a href="https://bugzilla.suse.com/show_bug.cgi?id=1111609">https://bugzilla.suse.com/show_bug.cgi?id=1111609</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17977">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17977</a>
          <a href="https://www.openwall.com/lists/oss-security/2018/10/05/5">https://www.openwall.com/lists/oss-security/2018/10/05/5</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2018-25020</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html">http://packetstormsecurity.com/files/165477/Kernel-Live-Patch-Security-Notice-LSN-0083-1.html</a>
          <a href="https://access.redhat.com/security/cve/CVE-2018-25020">https://access.redhat.com/security/cve/CVE-2018-25020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25020">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25020</a>
          <a href="https://git.kernel.org/linus/050fad7c4534c13c8eb1d9c2ba66012e014773cb (4.17-rc7)">https://git.kernel.org/linus/050fad7c4534c13c8eb1d9c2ba66012e014773cb (4.17-rc7)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=050fad7c4534c13c8eb1d9c2ba66012e014773cb">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=050fad7c4534c13c8eb1d9c2ba66012e014773cb</a>
          <a href="https://github.com/torvalds/linux/commit/050fad7c4534c13c8eb1d9c2ba66012e014773cb">https://github.com/torvalds/linux/commit/050fad7c4534c13c8eb1d9c2ba66012e014773cb</a>
          <a href="https://security.netapp.com/advisory/ntap-20211229-0005/">https://security.netapp.com/advisory/ntap-20211229-0005/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-24586</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-24586">https://access.redhat.com/security/cve/CVE-2020-24586</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24586">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24586</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-24586.html">https://linux.oracle.com/cve/CVE-2020-24586.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.3f8290e59823.I622a67769ed39257327a362cfc09c812320eb979@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.3f8290e59823.I622a67769ed39257327a362cfc09c812320eb979@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-24587</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-24587">https://access.redhat.com/security/cve/CVE-2020-24587</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24587">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24587</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-24587.html">https://linux.oracle.com/cve/CVE-2020-24587.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.3f8290e59823.I622a67769ed39257327a362cfc09c812320eb979@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.3f8290e59823.I622a67769ed39257327a362cfc09c812320eb979@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-24588</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-24588">https://access.redhat.com/security/cve/CVE-2020-24588</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24588">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24588</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-24588.html">https://linux.oracle.com/cve/CVE-2020-24588.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.25d93176ddaf.I9e265b597f2cd23eb44573f35b625947b386a9de@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.25d93176ddaf.I9e265b597f2cd23eb44573f35b625947b386a9de@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26139</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-26139">https://access.redhat.com/security/cve/CVE-2020-26139</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26139">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26139</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26139.html">https://linux.oracle.com/cve/CVE-2020-26139.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.cb327ed0cabe.Ib7dcffa2a31f0913d660de65ba3c8aca75b1d10f@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.cb327ed0cabe.Ib7dcffa2a31f0913d660de65ba3c8aca75b1d10f@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26141</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-26141">https://access.redhat.com/security/cve/CVE-2020-26141</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26141">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26141</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26141.html">https://linux.oracle.com/cve/CVE-2020-26141.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.c3f1d42c6746.I795593fcaae941c471425b8c7d5f7bb185d29142@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.c3f1d42c6746.I795593fcaae941c471425b8c7d5f7bb185d29142@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26145</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-26145">https://access.redhat.com/security/cve/CVE-2020-26145</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26145">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26145</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26145.html">https://linux.oracle.com/cve/CVE-2020-26145.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.9ca6ca7945a9.I1e18b514590af17c155bda86699bc3a971a8dcf4@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.9ca6ca7945a9.I1e18b514590af17c155bda86699bc3a971a8dcf4@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26147</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/12">http://www.openwall.com/lists/oss-security/2021/05/11/12</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-26147">https://access.redhat.com/security/cve/CVE-2020-26147</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-913875.pdf</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26147">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26147</a>
          <a href="https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md">https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26147.html">https://linux.oracle.com/cve/CVE-2020-26147.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9459.html">https://linux.oracle.com/errata/ELSA-2021-9459.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-wireless/20210511200110.30c4394bb835.I5acfdb552cc1d20c339c262315950b3eac491397@changeid/">https://lore.kernel.org/linux-wireless/20210511200110.30c4394bb835.I5acfdb552cc1d20c339c262315950b3eac491397@changeid/</a>
          <a href="https://papers.mathyvanhoef.com/usenix2021.pdf">https://papers.mathyvanhoef.com/usenix2021.pdf</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-faf-22epcEWu</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63">https://www.arista.com/en/support/advisories-notices/security-advisories/12602-security-advisory-63</a>
          <a href="https://www.fragattacks.com">https://www.fragattacks.com</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26541</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-26541">https://access.redhat.com/security/cve/CVE-2020-26541</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26541">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26541</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26541.html">https://linux.oracle.com/cve/CVE-2020-26541.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-2570.html">https://linux.oracle.com/errata/ELSA-2021-2570.html</a>
          <a href="https://lkml.org/lkml/2020/9/15/1871">https://lkml.org/lkml/2020/9/15/1871</a>
          <a href="https://lore.kernel.org/lkml/161428671215.677100.6372209948022011988.stgit@warthog.procyon.org.uk/">https://lore.kernel.org/lkml/161428671215.677100.6372209948022011988.stgit@warthog.procyon.org.uk/</a>
          <a href="https://lore.kernel.org/lkml/1884195.1615482306@warthog.procyon.org.uk/">https://lore.kernel.org/lkml/1884195.1615482306@warthog.procyon.org.uk/</a>
          <a href="https://lore.kernel.org/lkml/20200916004927.64276-1-eric.snowberg@oracle.com/">https://lore.kernel.org/lkml/20200916004927.64276-1-eric.snowberg@oracle.com/</a>
          <a href="https://lore.kernel.org/lkml/20210122181054.32635-1-eric.snowberg@oracle.com/">https://lore.kernel.org/lkml/20210122181054.32635-1-eric.snowberg@oracle.com/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-26541">https://nvd.nist.gov/vuln/detail/CVE-2020-26541</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5106-1">https://ubuntu.com/security/notices/USN-5106-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5210-1">https://ubuntu.com/security/notices/USN-5210-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-26558</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-26558">https://access.redhat.com/security/cve/CVE-2020-26558</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26558">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26558</a>
          <a href="https://kb.cert.org/vuls/id/799380">https://kb.cert.org/vuls/id/799380</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-26558.html">https://linux.oracle.com/cve/CVE-2020-26558.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4432.html">https://linux.oracle.com/errata/ELSA-2021-4432.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/</a>
          <a href="https://ubuntu.com/security/notices/USN-4989-1">https://ubuntu.com/security/notices/USN-4989-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4989-2">https://ubuntu.com/security/notices/USN-4989-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5017-1">https://ubuntu.com/security/notices/USN-5017-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5046-1">https://ubuntu.com/security/notices/USN-5046-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5050-1">https://ubuntu.com/security/notices/USN-5050-1</a>
          <a href="https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/passkey-entry/">https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/passkey-entry/</a>
          <a href="https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/">https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-27835</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-27835">https://access.redhat.com/security/cve/CVE-2020-27835</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1901709">https://bugzilla.redhat.com/show_bug.cgi?id=1901709</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27835">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27835</a>
          <a href="https://git.kernel.org/linus/3d2a9d642512c21a12d19b9250e7a835dcb41a79">https://git.kernel.org/linus/3d2a9d642512c21a12d19b9250e7a835dcb41a79</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-27835.html">https://linux.oracle.com/cve/CVE-2020-27835.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-1578.html">https://linux.oracle.com/errata/ELSA-2021-1578.html</a>
          <a href="https://ubuntu.com/security/notices/USN-4751-1">https://ubuntu.com/security/notices/USN-4751-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-36310</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-36310">https://access.redhat.com/security/cve/CVE-2020-36310</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1769283#c148">https://bugzilla.redhat.com/show_bug.cgi?id=1769283#c148</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.8">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.8</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36310">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36310</a>
          <a href="https://git.kernel.org/linus/e72436bc3a5206f95bb384e741154166ddb3202e">https://git.kernel.org/linus/e72436bc3a5206f95bb384e741154166ddb3202e</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e72436bc3a5206f95bb384e741154166ddb3202e">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e72436bc3a5206f95bb384e741154166ddb3202e</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-36310.html">https://linux.oracle.com/cve/CVE-2020-36310.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9307.html">https://linux.oracle.com/errata/ELSA-2021-9307.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-36322</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-36322">https://access.redhat.com/security/cve/CVE-2020-36322</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.6">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.6</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36322">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36322</a>
          <a href="https://git.kernel.org/linus/5d069dbe8aaf2a197142558b6fb2978189ba3454">https://git.kernel.org/linus/5d069dbe8aaf2a197142558b6fb2978189ba3454</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5d069dbe8aaf2a197142558b6fb2978189ba3454">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5d069dbe8aaf2a197142558b6fb2978189ba3454</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-36322.html">https://linux.oracle.com/cve/CVE-2020-36322.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-0063.html">https://linux.oracle.com/errata/ELSA-2022-0063.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-36385</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-36385">https://access.redhat.com/security/cve/CVE-2020-36385</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36385">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36385</a>
          <a href="https://git.kernel.org/linus/f5449e74802c1112dea984aec8af7a33c4516af1">https://git.kernel.org/linus/f5449e74802c1112dea984aec8af7a33c4516af1</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f5449e74802c1112dea984aec8af7a33c4516af1">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f5449e74802c1112dea984aec8af7a33c4516af1</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-36385.html">https://linux.oracle.com/cve/CVE-2020-36385.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4777.html">https://linux.oracle.com/errata/ELSA-2021-4777.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210720-0004/">https://security.netapp.com/advisory/ntap-20210720-0004/</a>
          <a href="https://sites.google.com/view/syzscope/kasan-use-after-free-read-in-ucma_close-2">https://sites.google.com/view/syzscope/kasan-use-after-free-read-in-ucma_close-2</a>
          <a href="https://syzkaller.appspot.com/bug?id=457491c4672d7b52c1007db213d93e47c711fae6">https://syzkaller.appspot.com/bug?id=457491c4672d7b52c1007db213d93e47c711fae6</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2020-3702</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-161.169</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-3702">https://access.redhat.com/security/cve/CVE-2020-3702</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3702">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3702</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://lore.kernel.org/linux-wireless/CABvG-CVvPF++0vuGzCrBj8+s=Bcx1GwWfiW1_Somu_GVncTAcQ@mail.gmail.com/">https://lore.kernel.org/linux-wireless/CABvG-CVvPF++0vuGzCrBj8+s=Bcx1GwWfiW1_Somu_GVncTAcQ@mail.gmail.com/</a>
          <a href="https://lore.kernel.org/stable/20210818084859.vcs4vs3yd6zetmyt@pali/t/#mf8b430d4f19f1b939a29b6c5098fdc514fd1a928">https://lore.kernel.org/stable/20210818084859.vcs4vs3yd6zetmyt@pali/t/#mf8b430d4f19f1b939a29b6c5098fdc514fd1a928</a>
          <a href="https://ubuntu.com/security/notices/USN-5113-1">https://ubuntu.com/security/notices/USN-5113-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5114-1">https://ubuntu.com/security/notices/USN-5114-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-1">https://ubuntu.com/security/notices/USN-5116-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-2">https://ubuntu.com/security/notices/USN-5116-2</a>
          <a href="https://www.arista.com/en/support/advisories-notices/security-advisories/11998-security-advisory-58">https://www.arista.com/en/support/advisories-notices/security-advisories/11998-security-advisory-58</a>
          <a href="https://www.debian.org/security/2021/dsa-4978">https://www.debian.org/security/2021/dsa-4978</a>
          <a href="https://www.qualcomm.com/company/product-security/bulletins/august-2020-bulletin">https://www.qualcomm.com/company/product-security/bulletins/august-2020-bulletin</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-0129</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-0129.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-0129.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-28950.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-28950.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3573.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3573.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3600.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3600.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3635.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3635.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-0129">https://access.redhat.com/security/cve/CVE-2021-0129</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0129">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0129</a>
          <a href="https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=00da0fb4972cf59e1c075f313da81ea549cb8738">https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=00da0fb4972cf59e1c075f313da81ea549cb8738</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6d19628f539fccf899298ff02ee4c73e4bf6df3f">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6d19628f539fccf899298ff02ee4c73e4bf6df3f</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-0129.html">https://linux.oracle.com/cve/CVE-2021-0129.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4356.html">https://linux.oracle.com/errata/ELSA-2021-4356.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210716-0002/">https://security.netapp.com/advisory/ntap-20210716-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5017-1">https://ubuntu.com/security/notices/USN-5017-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5046-1">https://ubuntu.com/security/notices/USN-5046-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5050-1">https://ubuntu.com/security/notices/USN-5050-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4951">https://www.debian.org/security/2021/dsa-4951</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-0920</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-159.167</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-0920">https://access.redhat.com/security/cve/CVE-2021-0920</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0920">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0920</a>
          <a href="https://git.kernel.org/linus/cbcf01128d0a92e131bd09f1688fe032480b65ca">https://git.kernel.org/linus/cbcf01128d0a92e131bd09f1688fe032480b65ca</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cbcf01128d0a92e131bd09f1688fe032480b65ca">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cbcf01128d0a92e131bd09f1688fe032480b65ca</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-0920.html">https://linux.oracle.com/cve/CVE-2021-0920.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-9014.html">https://linux.oracle.com/errata/ELSA-2022-9014.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://source.android.com/security/bulletin/2021-11-01">https://source.android.com/security/bulletin/2021-11-01</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-20320</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20320">https://access.redhat.com/security/cve/CVE-2021-20320</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20320">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20320</a>
          <a href="https://lore.kernel.org/bpf/20210902185229.1840281-1-johan.almbladh@anyfinetworks.com/">https://lore.kernel.org/bpf/20210902185229.1840281-1-johan.almbladh@anyfinetworks.com/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-20321</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20321">https://access.redhat.com/security/cve/CVE-2021-20321</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20321">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20321</a>
          <a href="https://git.kernel.org/linus/a295aef603e109a47af355477326bd41151765b6 (5.15-rc5)">https://git.kernel.org/linus/a295aef603e109a47af355477326bd41151765b6 (5.15-rc5)</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-20321.html">https://linux.oracle.com/cve/CVE-2021-20321.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-5227.html">https://linux.oracle.com/errata/ELSA-2021-5227.html</a>
          <a href="https://lore.kernel.org/all/20211011134508.748956131@linuxfoundation.org/">https://lore.kernel.org/all/20211011134508.748956131@linuxfoundation.org/</a>
          <a href="https://ubuntu.com/security/notices/USN-5208-1">https://ubuntu.com/security/notices/USN-5208-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5209-1">https://ubuntu.com/security/notices/USN-5209-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5210-1">https://ubuntu.com/security/notices/USN-5210-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5218-1">https://ubuntu.com/security/notices/USN-5218-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-22543</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-159.167</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/06/26/1">http://www.openwall.com/lists/oss-security/2021/06/26/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-22543">https://access.redhat.com/security/cve/CVE-2021-22543</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22543">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22543</a>
          <a href="https://github.com/google/security-research/security/advisories/GHSA-7wq5-phmq-m584">https://github.com/google/security-research/security/advisories/GHSA-7wq5-phmq-m584</a>
          <a href="https://github.com/torvalds/linux/commit/f8be156be163a052a067306417cd0ff679068c97">https://github.com/torvalds/linux/commit/f8be156be163a052a067306417cd0ff679068c97</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-22543.html">https://linux.oracle.com/cve/CVE-2021-22543.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9453.html">https://linux.oracle.com/errata/ELSA-2021-9453.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4G5YBUVEPHZYXMKNGBZ3S6INFCTEEL4E/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4G5YBUVEPHZYXMKNGBZ3S6INFCTEEL4E/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ROQIXQB7ZAWI3KSGSHR6H5RDUWZI775S/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ROQIXQB7ZAWI3KSGSHR6H5RDUWZI775S/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210708-0002/">https://security.netapp.com/advisory/ntap-20210708-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-1">https://ubuntu.com/security/notices/USN-5071-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-2">https://ubuntu.com/security/notices/USN-5071-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-3">https://ubuntu.com/security/notices/USN-5071-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5094-1">https://ubuntu.com/security/notices/USN-5094-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5094-2">https://ubuntu.com/security/notices/USN-5094-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5106-1">https://ubuntu.com/security/notices/USN-5106-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/26/3">https://www.openwall.com/lists/oss-security/2021/05/26/3</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/26/4">https://www.openwall.com/lists/oss-security/2021/05/26/4</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/26/5">https://www.openwall.com/lists/oss-security/2021/05/26/5</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-23134</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23134">https://access.redhat.com/security/cve/CVE-2021-23134</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23134">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23134</a>
          <a href="https://git.kernel.org/linus/c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6">https://git.kernel.org/linus/c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=c61760e6940d">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=c61760e6940d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-23134.html">https://linux.oracle.com/cve/CVE-2021-23134.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9453.html">https://linux.oracle.com/errata/ELSA-2021-9453.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZYORWNQIHNWRFYRDXBWYWBYM46PDZEN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LZYORWNQIHNWRFYRDXBWYWBYM46PDZEN/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QALNQT4LJFVSSA3MWCIECVY4AFPP4X77/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QALNQT4LJFVSSA3MWCIECVY4AFPP4X77/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23134">https://nvd.nist.gov/vuln/detail/CVE-2021-23134</a>
          <a href="https://security.netapp.com/advisory/ntap-20210625-0007/">https://security.netapp.com/advisory/ntap-20210625-0007/</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5016-1">https://ubuntu.com/security/notices/USN-5016-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/11/4">https://www.openwall.com/lists/oss-security/2021/05/11/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-26932</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://xenbits.xen.org/xsa/advisory-361.html">http://xenbits.xen.org/xsa/advisory-361.html</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26932">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26932</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-26932.html">https://linux.oracle.com/cve/CVE-2021-26932.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9136.html">https://linux.oracle.com/errata/ELSA-2021-9136.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/03/msg00035.html">https://lists.debian.org/debian-lts-announce/2021/03/msg00035.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2XQR52ICKRK3GC4HDWLMWF2U55YGAR63/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2XQR52ICKRK3GC4HDWLMWF2U55YGAR63/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GWQWPWYZRXVFJI5M3VCM72X27IB7CKOB/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GWQWPWYZRXVFJI5M3VCM72X27IB7CKOB/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-26932">https://nvd.nist.gov/vuln/detail/CVE-2021-26932</a>
          <a href="https://security.netapp.com/advisory/ntap-20210326-0001/">https://security.netapp.com/advisory/ntap-20210326-0001/</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/02/16/3">https://www.openwall.com/lists/oss-security/2021/02/16/3</a>
          <a href="https://xenbits.xen.org/xsa/advisory-361.html">https://xenbits.xen.org/xsa/advisory-361.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-29155</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-29155">https://access.redhat.com/security/cve/CVE-2021-29155</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29155">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29155</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-29155.html">https://linux.oracle.com/cve/CVE-2021-29155.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9363.html">https://linux.oracle.com/errata/ELSA-2021-9363.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CUX2CA63453G34C6KYVBLJXJXEARZI2X/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CUX2CA63453G34C6KYVBLJXJXEARZI2X/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PAEQ3H6HKNO6KUCGRZVYSFSAGEUX23JL/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PAEQ3H6HKNO6KUCGRZVYSFSAGEUX23JL/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XZASHZVCOFJ4VU2I3BN5W5EPHWJQ7QWX/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XZASHZVCOFJ4VU2I3BN5W5EPHWJQ7QWX/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-29155">https://nvd.nist.gov/vuln/detail/CVE-2021-29155</a>
          <a href="https://ubuntu.com/security/notices/USN-4977-1">https://ubuntu.com/security/notices/USN-4977-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4983-1">https://ubuntu.com/security/notices/USN-4983-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://www.kernel.org">https://www.kernel.org</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/04/18/4">https://www.openwall.com/lists/oss-security/2021/04/18/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-31829</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/04/4">http://www.openwall.com/lists/oss-security/2021/05/04/4</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-31829">https://access.redhat.com/security/cve/CVE-2021-31829</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31829">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31829</a>
          <a href="https://github.com/torvalds/linux/commit/801c6058d14a82179a7ee17a4b532cac6fad067f">https://github.com/torvalds/linux/commit/801c6058d14a82179a7ee17a4b532cac6fad067f</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-31829.html">https://linux.oracle.com/cve/CVE-2021-31829.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9363.html">https://linux.oracle.com/errata/ELSA-2021-9363.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VWCZ6LJLENL2C3URW5ICARTACXPFCFN2/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VWCZ6LJLENL2C3URW5ICARTACXPFCFN2/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y4X2G5YAPYJGI3PFEZZNOTRYI33GOCCZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Y4X2G5YAPYJGI3PFEZZNOTRYI33GOCCZ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZI7OBCJQDNWMKLBP6MZ5NV4EUTDAMX6Q/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZI7OBCJQDNWMKLBP6MZ5NV4EUTDAMX6Q/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-31829">https://nvd.nist.gov/vuln/detail/CVE-2021-31829</a>
          <a href="https://ubuntu.com/security/notices/USN-4983-1">https://ubuntu.com/security/notices/USN-4983-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-4999-1">https://ubuntu.com/security/notices/USN-4999-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/04/4">https://www.openwall.com/lists/oss-security/2021/05/04/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-32399</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/11/2">http://www.openwall.com/lists/oss-security/2021/05/11/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-32399">https://access.redhat.com/security/cve/CVE-2021-32399</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32399">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32399</a>
          <a href="https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e2cb6b891ad2b8caa9131e3be70f45243df82a80">https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e2cb6b891ad2b8caa9131e3be70f45243df82a80</a>
          <a href="https://github.com/torvalds/linux/commit/e2cb6b891ad2b8caa9131e3be70f45243df82a80">https://github.com/torvalds/linux/commit/e2cb6b891ad2b8caa9131e3be70f45243df82a80</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-32399.html">https://linux.oracle.com/cve/CVE-2021-32399.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9395.html">https://linux.oracle.com/errata/ELSA-2021-9395.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-32399">https://nvd.nist.gov/vuln/detail/CVE-2021-32399</a>
          <a href="https://security.netapp.com/advisory/ntap-20210622-0006/">https://security.netapp.com/advisory/ntap-20210622-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5016-1">https://ubuntu.com/security/notices/USN-5016-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/11/2">https://www.openwall.com/lists/oss-security/2021/05/11/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-33034</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33034">https://access.redhat.com/security/cve/CVE-2021-33034</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.4">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.4</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33034">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33034</a>
          <a href="https://git.kernel.org/linus/5c4c8c9544099bb9043a10a5318130a943e32fc3">https://git.kernel.org/linus/5c4c8c9544099bb9043a10a5318130a943e32fc3</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5c4c8c9544099bb9043a10a5318130a943e32fc3">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5c4c8c9544099bb9043a10a5318130a943e32fc3</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33034.html">https://linux.oracle.com/cve/CVE-2021-33034.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9363.html">https://linux.oracle.com/errata/ELSA-2021-9363.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GI7Z7UBWBGD3ABNIL2DC7RQDCGA4UVQW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GI7Z7UBWBGD3ABNIL2DC7RQDCGA4UVQW/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33034">https://nvd.nist.gov/vuln/detail/CVE-2021-33034</a>
          <a href="https://sites.google.com/view/syzscope/kasan-use-after-free-read-in-hci_send_acl">https://sites.google.com/view/syzscope/kasan-use-after-free-read-in-hci_send_acl</a>
          <a href="https://syzkaller.appspot.com/bug?id=2e1943a94647f7732dd6fc60368642d6e8dc91b1">https://syzkaller.appspot.com/bug?id=2e1943a94647f7732dd6fc60368642d6e8dc91b1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5016-1">https://ubuntu.com/security/notices/USN-5016-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5018-1">https://ubuntu.com/security/notices/USN-5018-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-33098</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33098">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33098</a>
          <a href="https://security.netapp.com/advisory/ntap-20211210-0005/">https://security.netapp.com/advisory/ntap-20211210-0005/</a>
          <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00555.html">https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00555.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-33624</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/06/21/1">http://www.openwall.com/lists/oss-security/2021/06/21/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-33624">https://access.redhat.com/security/cve/CVE-2021-33624</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33624">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33624</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=9183671af6dbf60a1219371d4ed73e23f43b49db">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=9183671af6dbf60a1219371d4ed73e23f43b49db</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=973377ffe8148180b2651825b92ae91988141b05">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=973377ffe8148180b2651825b92ae91988141b05</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=d203b0fd863a2261e5d00b97f3d060c4c2a6db71">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=d203b0fd863a2261e5d00b97f3d060c4c2a6db71</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=fe9a5ca7e370e613a9a75a13008a3845ea759d6e">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=fe9a5ca7e370e613a9a75a13008a3845ea759d6e</a>
          <a href="https://github.com/torvalds/linux/commit/9183671af6dbf60a1219371d4ed73e23f43b49db">https://github.com/torvalds/linux/commit/9183671af6dbf60a1219371d4ed73e23f43b49db</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33624">https://nvd.nist.gov/vuln/detail/CVE-2021-33624</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-1">https://ubuntu.com/security/notices/USN-5091-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-2">https://ubuntu.com/security/notices/USN-5091-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/06/21/1">https://www.openwall.com/lists/oss-security/2021/06/21/1</a>
          <a href="https://www.usenix.org/conference/usenixsecurity21/presentation/kirzner">https://www.usenix.org/conference/usenixsecurity21/presentation/kirzner</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-34556</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/01/3">http://www.openwall.com/lists/oss-security/2021/08/01/3</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-34556">https://access.redhat.com/security/cve/CVE-2021-34556</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34556">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34556</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=2039f26f3aca5b0e419b98f65dd36481337b86ee">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=2039f26f3aca5b0e419b98f65dd36481337b86ee</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=f5e81d1117501546b7be050c5fbafa6efd2c722c">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=f5e81d1117501546b7be050c5fbafa6efd2c722c</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/565ZS55ZFEN62WVRRORT7R63RXW5F4T4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/565ZS55ZFEN62WVRRORT7R63RXW5F4T4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6JKK6XNRZX5BT5QVYOKGVJ2BHFZAP5EX/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6JKK6XNRZX5BT5QVYOKGVJ2BHFZAP5EX/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-34556">https://nvd.nist.gov/vuln/detail/CVE-2021-34556</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/08/01/3">https://www.openwall.com/lists/oss-security/2021/08/01/3</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3506</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/08/1">http://www.openwall.com/lists/oss-security/2021/05/08/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3506">https://access.redhat.com/security/cve/CVE-2021-3506</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1944298">https://bugzilla.redhat.com/show_bug.cgi?id=1944298</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3506">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3506</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lore.kernel.org/lkml/20210322114730.71103-1-yuchao0@huawei.com/">https://lore.kernel.org/lkml/20210322114730.71103-1-yuchao0@huawei.com/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3506">https://nvd.nist.gov/vuln/detail/CVE-2021-3506</a>
          <a href="https://security.netapp.com/advisory/ntap-20210611-0007/">https://security.netapp.com/advisory/ntap-20210611-0007/</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-1">https://ubuntu.com/security/notices/USN-4997-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4997-2">https://ubuntu.com/security/notices/USN-4997-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-1">https://ubuntu.com/security/notices/USN-5000-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5000-2">https://ubuntu.com/security/notices/USN-5000-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5001-1">https://ubuntu.com/security/notices/USN-5001-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5016-1">https://ubuntu.com/security/notices/USN-5016-1</a>
          <a href="https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg2520013.html">https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg2520013.html</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/03/28/2">https://www.openwall.com/lists/oss-security/2021/03/28/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-35477</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-35477">https://access.redhat.com/security/cve/CVE-2021-35477</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35477">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35477</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=2039f26f3aca5b0e419b98f65dd36481337b86ee">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=2039f26f3aca5b0e419b98f65dd36481337b86ee</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=f5e81d1117501546b7be050c5fbafa6efd2c722c">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=f5e81d1117501546b7be050c5fbafa6efd2c722c</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/565ZS55ZFEN62WVRRORT7R63RXW5F4T4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/565ZS55ZFEN62WVRRORT7R63RXW5F4T4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6JKK6XNRZX5BT5QVYOKGVJ2BHFZAP5EX/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6JKK6XNRZX5BT5QVYOKGVJ2BHFZAP5EX/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-35477">https://nvd.nist.gov/vuln/detail/CVE-2021-35477</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/08/01/3">https://www.openwall.com/lists/oss-security/2021/08/01/3</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3564</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-154.161</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/25/1">http://www.openwall.com/lists/oss-security/2021/05/25/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/06/01/2">http://www.openwall.com/lists/oss-security/2021/06/01/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3564">https://access.redhat.com/security/cve/CVE-2021-3564</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1964139">https://bugzilla.redhat.com/show_bug.cgi?id=1964139</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3564">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3564</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3564.html">https://linux.oracle.com/cve/CVE-2021-3564.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9534.html">https://linux.oracle.com/errata/ELSA-2021-9534.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html">https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html</a>
          <a href="https://lore.kernel.org/linux-bluetooth/20210525123902.189012-1-gregkh@linuxfoundation.org/">https://lore.kernel.org/linux-bluetooth/20210525123902.189012-1-gregkh@linuxfoundation.org/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3564">https://nvd.nist.gov/vuln/detail/CVE-2021-3564</a>
          <a href="https://ubuntu.com/security/notices/USN-5015-1">https://ubuntu.com/security/notices/USN-5015-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5044-1">https://ubuntu.com/security/notices/USN-5044-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5045-1">https://ubuntu.com/security/notices/USN-5045-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5046-1">https://ubuntu.com/security/notices/USN-5046-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5050-1">https://ubuntu.com/security/notices/USN-5050-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/05/25/1">https://www.openwall.com/lists/oss-security/2021/05/25/1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3573</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-154.161</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-0129.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-0129.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-28950.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-28950.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3573.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3573.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3600.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3600.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3635.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3635.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3573">https://access.redhat.com/security/cve/CVE-2021-3573</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1966578">https://bugzilla.redhat.com/show_bug.cgi?id=1966578</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3573">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3573</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth.git/commit/?id=e305509e678b3a4af2b3cfd410f409f7cdaabb52">https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth.git/commit/?id=e305509e678b3a4af2b3cfd410f409f7cdaabb52</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3573.html">https://linux.oracle.com/cve/CVE-2021-3573.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9488.html">https://linux.oracle.com/errata/ELSA-2021-9488.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3573">https://nvd.nist.gov/vuln/detail/CVE-2021-3573</a>
          <a href="https://ubuntu.com/security/notices/USN-5015-1">https://ubuntu.com/security/notices/USN-5015-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5044-1">https://ubuntu.com/security/notices/USN-5044-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5045-1">https://ubuntu.com/security/notices/USN-5045-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5046-1">https://ubuntu.com/security/notices/USN-5046-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5050-1">https://ubuntu.com/security/notices/USN-5050-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/06/08/2">https://www.openwall.com/lists/oss-security/2021/06/08/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3612</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3612">https://access.redhat.com/security/cve/CVE-2021-3612</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1974079">https://bugzilla.redhat.com/show_bug.cgi?id=1974079</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3612">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3612</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3612.html">https://linux.oracle.com/cve/CVE-2021-3612.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9453.html">https://linux.oracle.com/errata/ELSA-2021-9453.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YKGI562LFV5MESTMVTCG5RORSBT6NGBN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YKGI562LFV5MESTMVTCG5RORSBT6NGBN/</a>
          <a href="https://lore.kernel.org/linux-input/20210620120030.1513655-1-avlarkin82@gmail.com/">https://lore.kernel.org/linux-input/20210620120030.1513655-1-avlarkin82@gmail.com/</a>
          <a href="https://lore.kernel.org/linux-input/20210620120030.1513655-1-avlarkin82@gmail.com/T/#u">https://lore.kernel.org/linux-input/20210620120030.1513655-1-avlarkin82@gmail.com/T/#u</a>
          <a href="https://security.netapp.com/advisory/ntap-20210805-0005/">https://security.netapp.com/advisory/ntap-20210805-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-1">https://ubuntu.com/security/notices/USN-5071-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-2">https://ubuntu.com/security/notices/USN-5071-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5071-3">https://ubuntu.com/security/notices/USN-5071-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-1">https://ubuntu.com/security/notices/USN-5073-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-2">https://ubuntu.com/security/notices/USN-5073-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-3">https://ubuntu.com/security/notices/USN-5073-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5106-1">https://ubuntu.com/security/notices/USN-5106-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3655</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3655">https://access.redhat.com/security/cve/CVE-2021-3655</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1984024">https://bugzilla.redhat.com/show_bug.cgi?id=1984024</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3655">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3655</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=f9beb95e6a2669fa35e34a6ff52808b181efa20f">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=f9beb95e6a2669fa35e34a6ff52808b181efa20f</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3655.html">https://linux.oracle.com/cve/CVE-2021-3655.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9488.html">https://linux.oracle.com/errata/ELSA-2021-9488.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://lore.kernel.org/netdev/599e6c1fdcc50f16597380118c9b3b6790241d50.1627439903.git.marcelo.leitner@gmail.com/">https://lore.kernel.org/netdev/599e6c1fdcc50f16597380118c9b3b6790241d50.1627439903.git.marcelo.leitner@gmail.com/</a>
          <a href="https://lore.kernel.org/netdev/e39b372644b6e5bf48df25e54b9172f34ec223a1.1624904195.git.marcelo.leitner@gmail.com/T/">https://lore.kernel.org/netdev/e39b372644b6e5bf48df25e54b9172f34ec223a1.1624904195.git.marcelo.leitner@gmail.com/T/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3655">https://nvd.nist.gov/vuln/detail/CVE-2021-3655</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5139-1">https://ubuntu.com/security/notices/USN-5139-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5161-1">https://ubuntu.com/security/notices/USN-5161-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5162-1">https://ubuntu.com/security/notices/USN-5162-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5163-1">https://ubuntu.com/security/notices/USN-5163-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3732</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-159.167</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3732">https://access.redhat.com/security/cve/CVE-2021-3732</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1995249">https://bugzilla.redhat.com/show_bug.cgi?id=1995249</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3732">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3732</a>
          <a href="https://git.kernel.org/linus/427215d85e8d1476da1a86b8d67aceb485eb3631">https://git.kernel.org/linus/427215d85e8d1476da1a86b8d67aceb485eb3631</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=427215d85e8d">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=427215d85e8d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3732.html">https://linux.oracle.com/cve/CVE-2021-3732.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9577.html">https://linux.oracle.com/errata/ELSA-2021-9577.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5094-1">https://ubuntu.com/security/notices/USN-5094-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5094-2">https://ubuntu.com/security/notices/USN-5094-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5113-1">https://ubuntu.com/security/notices/USN-5113-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-1">https://ubuntu.com/security/notices/USN-5116-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-2">https://ubuntu.com/security/notices/USN-5116-2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3743</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3743">https://access.redhat.com/security/cve/CVE-2021-3743</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3743">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3743</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=7e78c597c3eb">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=7e78c597c3eb</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=194ccc88297ae78d0803adad83c6dcc369787c9e">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=194ccc88297ae78d0803adad83c6dcc369787c9e</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7e78c597c3ebfd0cb329aa09a838734147e4f117">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7e78c597c3ebfd0cb329aa09a838734147e4f117</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ad9d24c9429e2159d1e279dc3a83191ccb4daf1d">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ad9d24c9429e2159d1e279dc3a83191ccb4daf1d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3743.html">https://linux.oracle.com/cve/CVE-2021-3743.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9475.html">https://linux.oracle.com/errata/ELSA-2021-9475.html</a>
          <a href="https://lists.openwall.net/netdev/2021/08/17/124">https://lists.openwall.net/netdev/2021/08/17/124</a>
          <a href="https://ubuntu.com/security/notices/USN-5113-1">https://ubuntu.com/security/notices/USN-5113-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5117-1">https://ubuntu.com/security/notices/USN-5117-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/08/27/2">https://www.openwall.com/lists/oss-security/2021/08/27/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3753</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3753">https://access.redhat.com/security/cve/CVE-2021-3753</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3753">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3753</a>
          <a href="https://git.kernel.org/linus/2287a51ba822384834dafc1c798453375d1107c7">https://git.kernel.org/linus/2287a51ba822384834dafc1c798453375d1107c7</a>
          <a href="https://github.com/torvalds/linux/commit/2287a51ba822384834dafc1c798453375d1107c7">https://github.com/torvalds/linux/commit/2287a51ba822384834dafc1c798453375d1107c7</a>
          <a href="https://ubuntu.com/security/notices/USN-5113-1">https://ubuntu.com/security/notices/USN-5113-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5117-1">https://ubuntu.com/security/notices/USN-5117-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/09/01/4">https://www.openwall.com/lists/oss-security/2021/09/01/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-37576</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-159.167</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/07/27/2">http://www.openwall.com/lists/oss-security/2021/07/27/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-37576">https://access.redhat.com/security/cve/CVE-2021-37576</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37576">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37576</a>
          <a href="https://git.kernel.org/linus/f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a (5.14-rc3)">https://git.kernel.org/linus/f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a (5.14-rc3)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f62f3c20647ebd5fb6ecb8f0b477b9281c44c10a</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-37576.html">https://linux.oracle.com/cve/CVE-2021-37576.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-3801.html">https://linux.oracle.com/errata/ELSA-2021-3801.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WDFA7DSQIPM7XPNXJBXFWXHJFVUBCAG6/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WDFA7DSQIPM7XPNXJBXFWXHJFVUBCAG6/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z2YZ2DNURMYYVDT2NYAFDESJC35KCUDS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z2YZ2DNURMYYVDT2NYAFDESJC35KCUDS/</a>
          <a href="https://lore.kernel.org/linuxppc-dev/87im0x1lqi.fsf@mpe.ellerman.id.au/T/#u">https://lore.kernel.org/linuxppc-dev/87im0x1lqi.fsf@mpe.ellerman.id.au/T/#u</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37576">https://nvd.nist.gov/vuln/detail/CVE-2021-37576</a>
          <a href="https://security.netapp.com/advisory/ntap-20210917-0005/">https://security.netapp.com/advisory/ntap-20210917-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-1">https://ubuntu.com/security/notices/USN-5091-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5094-1">https://ubuntu.com/security/notices/USN-5094-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4978">https://www.debian.org/security/2021/dsa-4978</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/07/26/1">https://www.openwall.com/lists/oss-security/2021/07/26/1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3759</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3759">https://access.redhat.com/security/cve/CVE-2021-3759</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3759">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3759</a>
          <a href="https://lore.kernel.org/linux-mm/1626333284-1404-1-git-send-email-nglaive@gmail.com/">https://lore.kernel.org/linux-mm/1626333284-1404-1-git-send-email-nglaive@gmail.com/</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5117-1">https://ubuntu.com/security/notices/USN-5117-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5135-1">https://ubuntu.com/security/notices/USN-5135-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-2">https://ubuntu.com/security/notices/USN-5137-2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3760</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3760">https://access.redhat.com/security/cve/CVE-2021-3760</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3760">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3760</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1b1499a817c90fd1ce9453a2c98d2a01cca0e775">https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1b1499a817c90fd1ce9453a2c98d2a01cca0e775</a>
          <a href="https://ubuntu.com/security/notices/USN-5139-1">https://ubuntu.com/security/notices/USN-5139-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5165-1">https://ubuntu.com/security/notices/USN-5165-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5208-1">https://ubuntu.com/security/notices/USN-5208-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5209-1">https://ubuntu.com/security/notices/USN-5209-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5210-1">https://ubuntu.com/security/notices/USN-5210-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5218-1">https://ubuntu.com/security/notices/USN-5218-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/10/26/2">https://www.openwall.com/lists/oss-security/2021/10/26/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3764</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-163.171</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3764">https://access.redhat.com/security/cve/CVE-2021-3764</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3764">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3764</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=36cf515b9bbe">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=36cf515b9bbe</a>
          <a href="https://ubuntu.com/security/notices/USN-5139-1">https://ubuntu.com/security/notices/USN-5139-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5140-1">https://ubuntu.com/security/notices/USN-5140-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5161-1">https://ubuntu.com/security/notices/USN-5161-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5162-1">https://ubuntu.com/security/notices/USN-5162-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5163-1">https://ubuntu.com/security/notices/USN-5163-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5164-1">https://ubuntu.com/security/notices/USN-5164-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-38160</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38160">https://access.redhat.com/security/cve/CVE-2021-38160</a>
          <a href="https://access.redhat.com/security/cve/cve-2021-38160">https://access.redhat.com/security/cve/cve-2021-38160</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38160">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38160</a>
          <a href="https://git.kernel.org/linus/d00d8da5869a2608e97cfede094dfc5e11462a46">https://git.kernel.org/linus/d00d8da5869a2608e97cfede094dfc5e11462a46</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d00d8da5869a2608e97cfede094dfc5e11462a46">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d00d8da5869a2608e97cfede094dfc5e11462a46</a>
          <a href="https://github.com/torvalds/linux/commit/d00d8da5869a2608e97cfede094dfc5e11462a46">https://github.com/torvalds/linux/commit/d00d8da5869a2608e97cfede094dfc5e11462a46</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-38160.html">https://linux.oracle.com/cve/CVE-2021-38160.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9488.html">https://linux.oracle.com/errata/ELSA-2021-9488.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38160">https://nvd.nist.gov/vuln/detail/CVE-2021-38160</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0010/">https://security.netapp.com/advisory/ntap-20210902-0010/</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-1">https://ubuntu.com/security/notices/USN-5073-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-2">https://ubuntu.com/security/notices/USN-5073-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5073-3">https://ubuntu.com/security/notices/USN-5073-3</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-1">https://ubuntu.com/security/notices/USN-5091-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-2">https://ubuntu.com/security/notices/USN-5091-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5106-1">https://ubuntu.com/security/notices/USN-5106-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4978">https://www.debian.org/security/2021/dsa-4978</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-38198</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-161.169</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38198">https://access.redhat.com/security/cve/CVE-2021-38198</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.11">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.11</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38198">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38198</a>
          <a href="https://github.com/torvalds/linux/commit/b1bd5cba3306691c771d558e94baa73e8b0b96b7">https://github.com/torvalds/linux/commit/b1bd5cba3306691c771d558e94baa73e8b0b96b7</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-38198.html">https://linux.oracle.com/cve/CVE-2021-38198.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9475.html">https://linux.oracle.com/errata/ELSA-2021-9475.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38198">https://nvd.nist.gov/vuln/detail/CVE-2021-38198</a>
          <a href="https://ubuntu.com/security/notices/USN-5070-1">https://ubuntu.com/security/notices/USN-5070-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5114-1">https://ubuntu.com/security/notices/USN-5114-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-1">https://ubuntu.com/security/notices/USN-5116-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-2">https://ubuntu.com/security/notices/USN-5116-2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-38199</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38199">https://access.redhat.com/security/cve/CVE-2021-38199</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.4</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38199">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38199</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dd99e9f98fbf423ff6d365b37a98e8879170f17c">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dd99e9f98fbf423ff6d365b37a98e8879170f17c</a>
          <a href="https://github.com/torvalds/linux/commit/dd99e9f98fbf423ff6d365b37a98e8879170f17c">https://github.com/torvalds/linux/commit/dd99e9f98fbf423ff6d365b37a98e8879170f17c</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38199">https://nvd.nist.gov/vuln/detail/CVE-2021-38199</a>
          <a href="https://security.netapp.com/advisory/ntap-20210902-0010/">https://security.netapp.com/advisory/ntap-20210902-0010/</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-1">https://ubuntu.com/security/notices/USN-5091-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5091-2">https://ubuntu.com/security/notices/USN-5091-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-1">https://ubuntu.com/security/notices/USN-5092-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5092-2">https://ubuntu.com/security/notices/USN-5092-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5106-1">https://ubuntu.com/security/notices/USN-5106-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4978">https://www.debian.org/security/2021/dsa-4978</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-38208</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-154.161</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/1">http://www.openwall.com/lists/oss-security/2021/08/17/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/17/2">http://www.openwall.com/lists/oss-security/2021/08/17/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/08/24/2">http://www.openwall.com/lists/oss-security/2021/08/24/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-38208">https://access.redhat.com/security/cve/CVE-2021-38208</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1992810">https://bugzilla.redhat.com/show_bug.cgi?id=1992810</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.10">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.10</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38208">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38208</a>
          <a href="https://github.com/torvalds/linux/commit/4ac06a1e013cf5fdd963317ffd3b968560f33bba">https://github.com/torvalds/linux/commit/4ac06a1e013cf5fdd963317ffd3b968560f33bba</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38208">https://nvd.nist.gov/vuln/detail/CVE-2021-38208</a>
          <a href="https://ubuntu.com/security/notices/USN-5050-1">https://ubuntu.com/security/notices/USN-5050-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-3864</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3864">https://access.redhat.com/security/cve/CVE-2021-3864</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3864">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3864</a>
          <a href="https://lore.kernel.org/all/20211221021744.864115-1-longman@redhat.com">https://lore.kernel.org/all/20211221021744.864115-1-longman@redhat.com</a>
          <a href="https://lore.kernel.org/all/20211226150310.GA992@1wt.eu/">https://lore.kernel.org/all/20211226150310.GA992@1wt.eu/</a>
          <a href="https://lore.kernel.org/lkml/20211228170910.623156-1-wander@redhat.com">https://lore.kernel.org/lkml/20211228170910.623156-1-wander@redhat.com</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/10/20/2">https://www.openwall.com/lists/oss-security/2021/10/20/2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-39633</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39633">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39633</a>
          <a href="https://git.kernel.org/linus/1d011c4803c72f3907eccfc1ec63caefb852fcbf (5.14)">https://git.kernel.org/linus/1d011c4803c72f3907eccfc1ec63caefb852fcbf (5.14)</a>
          <a href="https://source.android.com/security/bulletin/2022-01-01">https://source.android.com/security/bulletin/2022-01-01</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4037</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4037">https://access.redhat.com/security/cve/CVE-2021-4037</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4037">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4037</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=01ea173e103e">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=01ea173e103e</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0fa3ecd87848">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0fa3ecd87848</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-40490</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-161.169</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-40490">https://access.redhat.com/security/cve/CVE-2021-40490</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40490">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40490</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/tytso/ext4.git/commit/?id=9e445093e523f3277081314c864f708fd4bd34aa">https://git.kernel.org/pub/scm/linux/kernel/git/tytso/ext4.git/commit/?id=9e445093e523f3277081314c864f708fd4bd34aa</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-40490.html">https://linux.oracle.com/cve/CVE-2021-40490.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9488.html">https://linux.oracle.com/errata/ELSA-2021-9488.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html">https://lists.debian.org/debian-lts-announce/2021/10/msg00010.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00012.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M6VS2DLGT7TK7URKAS2KWJL3S533SGVA/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M6VS2DLGT7TK7URKAS2KWJL3S533SGVA/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJGX3DMJT6MRBW2XEF3TWVHYWZW3DG3N/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJGX3DMJT6MRBW2XEF3TWVHYWZW3DG3N/</a>
          <a href="https://lore.kernel.org/linux-ext4/000000000000e5080305c9e51453@google.com/">https://lore.kernel.org/linux-ext4/000000000000e5080305c9e51453@google.com/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-40490">https://nvd.nist.gov/vuln/detail/CVE-2021-40490</a>
          <a href="https://security.netapp.com/advisory/ntap-20211004-0001/">https://security.netapp.com/advisory/ntap-20211004-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-5096-1">https://ubuntu.com/security/notices/USN-5096-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5113-1">https://ubuntu.com/security/notices/USN-5113-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5114-1">https://ubuntu.com/security/notices/USN-5114-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5115-1">https://ubuntu.com/security/notices/USN-5115-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-1">https://ubuntu.com/security/notices/USN-5116-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5116-2">https://ubuntu.com/security/notices/USN-5116-2</a>
          <a href="https://ubuntu.com/security/notices/USN-5120-1">https://ubuntu.com/security/notices/USN-5120-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4978">https://www.debian.org/security/2021/dsa-4978</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4149</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4149">https://access.redhat.com/security/cve/CVE-2021-4149</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4149">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4149</a>
          <a href="https://git.kernel.org/linus/19ea40dddf1833db868533958ca066f368862211 (5.15-rc6)">https://git.kernel.org/linus/19ea40dddf1833db868533958ca066f368862211 (5.15-rc6)</a>
          <a href="https://lkml.org/lkml/2021/10/18/885">https://lkml.org/lkml/2021/10/18/885</a>
          <a href="https://lkml.org/lkml/2021/9/13/2565">https://lkml.org/lkml/2021/9/13/2565</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4150</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4150">https://access.redhat.com/security/cve/CVE-2021-4150</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4150">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4150</a>
          <a href="https://git.kernel.org/linus/9fbfabfda25d8774c5a08634fdd2da000a924890 (5.15-rc7)">https://git.kernel.org/linus/9fbfabfda25d8774c5a08634fdd2da000a924890 (5.15-rc7)</a>
          <a href="https://lkml.org/lkml/2021/10/18/485">https://lkml.org/lkml/2021/10/18/485</a>
          <a href="https://lkml.org/lkml/2021/9/6/781">https://lkml.org/lkml/2021/9/6/781</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4157</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-151.157</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4157">https://access.redhat.com/security/cve/CVE-2021-4157</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4157">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4157</a>
          <a href="https://git.kernel.org/linus/ed34695e15aba74f45247f1ee2cf7e09d449f925 (5.13-rc1)">https://git.kernel.org/linus/ed34695e15aba74f45247f1ee2cf7e09d449f925 (5.13-rc1)</a>
          <a href="https://lore.kernel.org/lkml/20210517140244.822185482@linuxfoundation.org/">https://lore.kernel.org/lkml/20210517140244.822185482@linuxfoundation.org/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4197</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4197">https://access.redhat.com/security/cve/CVE-2021-4197</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2035652">https://bugzilla.redhat.com/show_bug.cgi?id=2035652</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4197">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4197</a>
          <a href="https://lore.kernel.org/lkml/20211209214707.805617-1-tj@kernel.org/T/">https://lore.kernel.org/lkml/20211209214707.805617-1-tj@kernel.org/T/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-4203</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-163.171</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4203">https://access.redhat.com/security/cve/CVE-2021-4203</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2230">https://bugs.chromium.org/p/project-zero/issues/detail?id=2230</a>
          <a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=2230&amp;can=7&amp;q=modified-after%3Atoday-30&amp;sort=-modified&amp;colspec=ID%20Type%20Status%20Priority%20Milestone%20Owner%20Summary%20Modified%20Cve&amp;cells=tiles&amp;redir=1">https://bugs.chromium.org/p/project-zero/issues/detail?id=2230&amp;can=7&amp;q=modified-after%3Atoday-30&amp;sort=-modified&amp;colspec=ID%20Type%20Status%20Priority%20Milestone%20Owner%20Summary%20Modified%20Cve&amp;cells=tiles&amp;redir=1</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4203">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4203</a>
          <a href="https://git.kernel.org/linus/35306eb23814444bd4021f8a1c3047d3cb0c8b2b (5.15-rc4)">https://git.kernel.org/linus/35306eb23814444bd4021f8a1c3047d3cb0c8b2b (5.15-rc4)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=35306eb23814">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=35306eb23814</a>
          <a href="https://lore.kernel.org/netdev/20210929225750.2548112-1-eric.dumazet@gmail.com/T/">https://lore.kernel.org/netdev/20210929225750.2548112-1-eric.dumazet@gmail.com/T/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-42252</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-162.170</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42252">https://access.redhat.com/security/cve/CVE-2021-42252</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.14.6">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.14.6</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42252">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42252</a>
          <a href="https://git.kernel.org/linus/b49a0e69a7b1a68c8d3f64097d06dabb770fec96 (5.15-rc1)">https://git.kernel.org/linus/b49a0e69a7b1a68c8d3f64097d06dabb770fec96 (5.15-rc1)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b49a0e69a7b1a68c8d3f64097d06dabb770fec96">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b49a0e69a7b1a68c8d3f64097d06dabb770fec96</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42252">https://nvd.nist.gov/vuln/detail/CVE-2021-42252</a>
          <a href="https://security.netapp.com/advisory/ntap-20211112-0006/">https://security.netapp.com/advisory/ntap-20211112-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-5136-1">https://ubuntu.com/security/notices/USN-5136-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5137-1">https://ubuntu.com/security/notices/USN-5137-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5161-1">https://ubuntu.com/security/notices/USN-5161-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5162-1">https://ubuntu.com/security/notices/USN-5162-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-43975</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-43975">https://access.redhat.com/security/cve/CVE-2021-43975</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43975">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43975</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=b922f622592af76b57cbc566eaeccda0b31a3496">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=b922f622592af76b57cbc566eaeccda0b31a3496</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X24M7KDC4OJOZNS3RDSYC7ELNELOLQ2N/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X24M7KDC4OJOZNS3RDSYC7ELNELOLQ2N/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YODMYMGZYDXQKGJGX7TJG4XV4L5YLLBD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YODMYMGZYDXQKGJGX7TJG4XV4L5YLLBD/</a>
          <a href="https://lore.kernel.org/netdev/163698540868.13805.17800408021782408762.git-patchwork-notify@kernel.org/T/">https://lore.kernel.org/netdev/163698540868.13805.17800408021782408762.git-patchwork-notify@kernel.org/T/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-43975">https://nvd.nist.gov/vuln/detail/CVE-2021-43975</a>
          <a href="https://security.netapp.com/advisory/ntap-20211210-0001/">https://security.netapp.com/advisory/ntap-20211210-0001/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-44733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-44733">https://access.redhat.com/security/cve/CVE-2021-44733</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2030747">https://bugzilla.redhat.com/show_bug.cgi?id=2030747</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44733</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/tee/tee_shm.c">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/tee/tee_shm.c</a>
          <a href="https://github.com/pjlantz/optee-qemu/blob/main/README.md">https://github.com/pjlantz/optee-qemu/blob/main/README.md</a>
          <a href="https://lore.kernel.org/lkml/20211214123540.1789434-1-jens.wiklander@linaro.org/">https://lore.kernel.org/lkml/20211214123540.1789434-1-jens.wiklander@linaro.org/</a>
          <a href="https://lore.kernel.org/lkml/20211215092501.1861229-1-jens.wiklander@linaro.org/">https://lore.kernel.org/lkml/20211215092501.1861229-1-jens.wiklander@linaro.org/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44733">https://nvd.nist.gov/vuln/detail/CVE-2021-44733</a>
          <a href="https://security.netapp.com/advisory/ntap-20220114-0003/">https://security.netapp.com/advisory/ntap-20220114-0003/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-45095</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45095">https://access.redhat.com/security/cve/CVE-2021-45095</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45095">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45095</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=bcd0f93353326954817a4f9fa55ec57fb38acbb0">https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=bcd0f93353326954817a4f9fa55ec57fb38acbb0</a>
          <a href="https://github.com/torvalds/linux/commit/bcd0f93353326954817a4f9fa55ec57fb38acbb0">https://github.com/torvalds/linux/commit/bcd0f93353326954817a4f9fa55ec57fb38acbb0</a>
          <a href="https://lore.kernel.org/all/20211209082839.33985-1-hbh25y@gmail.com/">https://lore.kernel.org/all/20211209082839.33985-1-hbh25y@gmail.com/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45095">https://nvd.nist.gov/vuln/detail/CVE-2021-45095</a>
          <a href="https://www.debian.org/security/2022/dsa-5050">https://www.debian.org/security/2022/dsa-5050</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-45469</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/12/25/1">http://www.openwall.com/lists/oss-security/2021/12/25/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-45469">https://access.redhat.com/security/cve/CVE-2021-45469</a>
          <a href="https://bugzilla.kernel.org/show_bug.cgi?id=215235">https://bugzilla.kernel.org/show_bug.cgi?id=215235</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45469">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45469</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/chao/linux.git/commit/?h=dev&amp;id=5598b24efaf4892741c798b425d543e4bed357a1">https://git.kernel.org/pub/scm/linux/kernel/git/chao/linux.git/commit/?h=dev&amp;id=5598b24efaf4892741c798b425d543e4bed357a1</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AK2C4A43BZSWATZWFUHHHUQF3HPIALNP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AK2C4A43BZSWATZWFUHHHUQF3HPIALNP/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QG7XV2WXKMSMKIQKIBG5LW3Y3GXEWG5Q/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QG7XV2WXKMSMKIQKIBG5LW3Y3GXEWG5Q/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45469">https://nvd.nist.gov/vuln/detail/CVE-2021-45469</a>
          <a href="https://security.netapp.com/advisory/ntap-20220114-0003/">https://security.netapp.com/advisory/ntap-20220114-0003/</a>
          <a href="https://www.debian.org/security/2022/dsa-5050">https://www.debian.org/security/2022/dsa-5050</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-45485</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45485">https://access.redhat.com/security/cve/CVE-2021-45485</a>
          <a href="https://arxiv.org/pdf/2112.09604.pdf">https://arxiv.org/pdf/2112.09604.pdf</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.3">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.13.3</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45485">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45485</a>
          <a href="https://git.kernel.org/linus/62f20e068ccc50d6ab66fdb72ba90da2b9418c99 (5.14-rc1)">https://git.kernel.org/linus/62f20e068ccc50d6ab66fdb72ba90da2b9418c99 (5.14-rc1)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=62f20e068ccc50d6ab66fdb72ba90da2b9418c99">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=62f20e068ccc50d6ab66fdb72ba90da2b9418c99</a>
          <a href="https://lore.kernel.org/all/20210529110746.6796-1-w@1wt.eu/">https://lore.kernel.org/all/20210529110746.6796-1-w@1wt.eu/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45485">https://nvd.nist.gov/vuln/detail/CVE-2021-45485</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0001/">https://security.netapp.com/advisory/ntap-20220121-0001/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2021-45486</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-156.163</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45486">https://access.redhat.com/security/cve/CVE-2021-45486</a>
          <a href="https://arxiv.org/pdf/2112.09604.pdf">https://arxiv.org/pdf/2112.09604.pdf</a>
          <a href="https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.4">https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.12.4</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45486">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45486</a>
          <a href="https://git.kernel.org/linus/aa6dd211e4b1dde9d5dc25d699d35f789ae7eeba (5.13-rc1)">https://git.kernel.org/linus/aa6dd211e4b1dde9d5dc25d699d35f789ae7eeba (5.13-rc1)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/net/ipv4/route.c?id=aa6dd211e4b1dde9d5dc25d699d35f789ae7eeba">https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/net/ipv4/route.c?id=aa6dd211e4b1dde9d5dc25d699d35f789ae7eeba</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45486">https://nvd.nist.gov/vuln/detail/CVE-2021-45486</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2022-0322</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.15.0-147.151</td>
        <td>4.15.0-166.174</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0322">https://access.redhat.com/security/cve/CVE-2022-0322</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0322">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0322</a>
          <a href="https://git.kernel.org/linus/a2d859e3fc97e79d907761550dbc03ff1b36479c (5.15-rc6)">https://git.kernel.org/linus/a2d859e3fc97e79d907761550dbc03ff1b36479c (5.15-rc6)</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a2d859e3fc97e79d907761550dbc03ff1b36479c">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a2d859e3fc97e79d907761550dbc03ff1b36479c</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">locales</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-38604</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-38604">https://access.redhat.com/security/cve/CVE-2021-38604</a>
          <a href="https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc">https://blog.tuxcare.com/cve/tuxcare-team-identifies-cve-2021-38604-a-new-vulnerability-in-glibc</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38604</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GYEXYM37RCJWJ6B5KQUYQI4NZBDDYSXP/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38604">https://nvd.nist.gov/vuln/detail/CVE-2021-38604</a>
          <a href="https://security.netapp.com/advisory/ntap-20210909-0005/">https://security.netapp.com/advisory/ntap-20210909-0005/</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28213">https://sourceware.org/bugzilla/show_bug.cgi?id=28213</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641">https://sourceware.org/git/?p=glibc.git;a=commit;h=4cc79c217744743077bf7a0ec5e0a4318f1e6641</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8">https://sourceware.org/git/?p=glibc.git;a=commit;h=b805aebd42364fe696e417808a700fdb9800c9e8</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2021-3999</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3999">https://access.redhat.com/security/cve/CVE-2021-3999</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3999</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/24/4">https://www.openwall.com/lists/oss-security/2022/01/24/4</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2022-23218</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23218">https://access.redhat.com/security/cve/CVE-2022-23218</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23218">https://nvd.nist.gov/vuln/detail/CVE-2022-23218</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=28768">https://sourceware.org/bugzilla/show_bug.cgi?id=28768</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">multiarch-support</td>
        <td>CVE-2022-23219</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.27-3ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-23219">https://access.redhat.com/security/cve/CVE-2022-23219</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23219</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23219">https://nvd.nist.gov/vuln/detail/CVE-2022-23219</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=22542">https://sourceware.org/bugzilla/show_bug.cgi?id=22542</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">nginx</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">nginx-common</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">nginx-core</td>
        <td>CVE-2020-11724</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.14.0-0ubuntu1.9</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11724</a>
          <a href="https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa">https://github.com/openresty/lua-nginx-module/commit/9ab38e8ee35fc08a57636b1b6190dca70b0076fa</a>
          <a href="https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch">https://github.com/openresty/openresty/blob/4e8b4c395f842a078e429c80dd063b2323999957/patches/ngx_http_lua-0.10.15-fix_location_capture_content_length_chunked.patch</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html">https://lists.debian.org/debian-lts-announce/2020/07/msg00014.html</a>
          <a href="https://security.netapp.com/advisory/ntap-20210129-0002/">https://security.netapp.com/advisory/ntap-20210129-0002/</a>
          <a href="https://www.debian.org/security/2020/dsa-4750">https://www.debian.org/security/2020/dsa-4750</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-3711</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/08/26/2">http://www.openwall.com/lists/oss-security/2021/08/26/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3711">https://access.redhat.com/security/cve/CVE-2021-3711</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=59f5e75f3bced8fc0e130d72a3f582cf7b480b46</a>
          <a href="https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r18995de860f0e63635f3008fd2a6aca82394249476d21691e7c59c9e@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/rad5d9f83f0d11fb3f8bb148d179b8a9ad7c6a17f18d70e5805a713d1@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3711">https://nvd.nist.gov/vuln/detail/CVE-2021-3711</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0097.html">https://rustsec.org/advisories/RUSTSEC-2021-0097.html</a>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">openssl</td>
        <td>CVE-2021-3712</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1-1ubuntu2.1~18.04.9</td>
        <td>1.1.1-1ubuntu2.1~18.04.13</td>
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
        <td class="pkg-name">perl</td>
        <td>CVE-2020-16156</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.26.1-6ubuntu0.5</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">perl-base</td>
        <td>CVE-2020-16156</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.26.1-6ubuntu0.5</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">perl-modules-5.26</td>
        <td>CVE-2020-16156</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">5.26.1-6ubuntu0.5</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-dev</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-dev</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-dev</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-minimal</td>
        <td>CVE-2021-3733</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3733">https://access.redhat.com/security/cve/CVE-2021-3733</a>
          <a href="https://bugs.python.org/issue43075">https://bugs.python.org/issue43075</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3733</a>
          <a href="https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final">https://docs.python.org/3.6/whatsnew/changelog.html#python-3-6-14-final</a>
          <a href="https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final">https://docs.python.org/3.7/whatsnew/changelog.html#python-3-7-11-final</a>
          <a href="https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final">https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-10-final</a>
          <a href="https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final">https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-5-final</a>
          <a href="https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)">https://github.com/python/cpython/commit/3fbe96123aeb66664fa547a8f6022efa2dc8788f (3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)">https://github.com/python/cpython/commit/7215d1ae25525c92b026166f9d5cac85fb1defe1 (master)</a>
          <a href="https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)">https://github.com/python/cpython/commit/a21d4fbd549ec9685068a113660553d7f80d9b09 (3.9.5)</a>
          <a href="https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)">https://github.com/python/cpython/commit/ada14995870abddc277addf57dd690a2af04c2da (3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)">https://github.com/python/cpython/commit/e7654b6046090914a8323931ed759a94a5f85d60 (3.8.10)</a>
          <a href="https://github.com/python/cpython/pull/24391">https://github.com/python/cpython/pull/24391</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3733.html">https://linux.oracle.com/cve/CVE-2021-3733.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-minimal</td>
        <td>CVE-2021-3737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td>3.6.9-1~18.04ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3737">https://access.redhat.com/security/cve/CVE-2021-3737</a>
          <a href="https://bugs.python.org/issue44022">https://bugs.python.org/issue44022</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3737</a>
          <a href="https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)">https://github.com/python/cpython/commit/0389426fa4af4dfc8b1d7f3f291932d928392d8b (3.8 branch)</a>
          <a href="https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)">https://github.com/python/cpython/commit/078b146f062d212919d0ba25e34e658a8234aa63 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14">https://github.com/python/cpython/commit/1b6f4e5e13ebd1f957b47f7415b53d0869bdbac6 (v3.6.14</a>
          <a href="https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)">https://github.com/python/cpython/commit/5df4abd6b033a5f1e48945c6988b45e35e76f647 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)">https://github.com/python/cpython/commit/60ba0b68470a584103e28958d91e93a6db37ec92 (v3.10.0b2)</a>
          <a href="https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)">https://github.com/python/cpython/commit/98e5a7975d99b58d511f171816ecdfb13d5cca18 (v3.10.0b3)</a>
          <a href="https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)">https://github.com/python/cpython/commit/ea9327036680acc92d9f89eaf6f6a54d2f8d78d9 (v3.9.6)</a>
          <a href="https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)">https://github.com/python/cpython/commit/f396864ddfe914531b5856d7bf852808ebfc01ae (v3.8.11)</a>
          <a href="https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)">https://github.com/python/cpython/commit/f68d2d69f1da56c2aea1293ecf93ab69a6010ad7 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)">https://github.com/python/cpython/commit/fee96422e6f0056561cf74fef2012cc066c9db86 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/pull/25916">https://github.com/python/cpython/pull/25916</a>
          <a href="https://github.com/python/cpython/pull/26503">https://github.com/python/cpython/pull/26503</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3737.html">https://linux.oracle.com/cve/CVE-2021-3737.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4160.html">https://linux.oracle.com/errata/ELSA-2021-4160.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5083-1">https://ubuntu.com/security/notices/USN-5083-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5199-1">https://ubuntu.com/security/notices/USN-5199-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5200-1">https://ubuntu.com/security/notices/USN-5200-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5201-1">https://ubuntu.com/security/notices/USN-5201-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">python3.6-minimal</td>
        <td>CVE-2021-4189</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.6.9-1~18.04ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-4189">https://access.redhat.com/security/cve/CVE-2021-4189</a>
          <a href="https://bugs.python.org/issue43285">https://bugs.python.org/issue43285</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2036020">https://bugzilla.redhat.com/show_bug.cgi?id=2036020</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4189</a>
          <a href="https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)">https://github.com/python/cpython/commit/0ab152c6b5d95caa2dc1a30fa96e10258b5f188e (master)</a>
          <a href="https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)">https://github.com/python/cpython/commit/4134f154ae2f621f25c5d698cc0f1748035a1b88 (v3.6.14)</a>
          <a href="https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)">https://github.com/python/cpython/commit/79373951b3eab585d42e0f0ab83718cbe1d0ee33 (v3.7.11)</a>
          <a href="https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)">https://github.com/python/cpython/commit/7dcb4baa4f0fde3aef5122a8e9f6a41853ec9335 (v3.9.3)</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-3778</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3778">https://access.redhat.com/security/cve/CVE-2021-3778</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778</a>
          <a href="https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f">https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f</a>
          <a href="https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273">https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3778.html">https://linux.oracle.com/cve/CVE-2021-3778.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3778">https://nvd.nist.gov/vuln/detail/CVE-2021-3778</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-3796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3796">https://access.redhat.com/security/cve/CVE-2021-3796</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796</a>
          <a href="https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3">https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3</a>
          <a href="https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d">https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3796.html">https://linux.oracle.com/cve/CVE-2021-3796.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3796">https://nvd.nist.gov/vuln/detail/CVE-2021-3796</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-3927</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3927">https://access.redhat.com/security/cve/CVE-2021-3927</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927</a>
          <a href="https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e">https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e</a>
          <a href="https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0">https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3927">https://nvd.nist.gov/vuln/detail/CVE-2021-3927</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-3928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3928">https://access.redhat.com/security/cve/CVE-2021-3928</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928</a>
          <a href="https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732">https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732</a>
          <a href="https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd">https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3928">https://nvd.nist.gov/vuln/detail/CVE-2021-3928</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-3984</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3984">https://access.redhat.com/security/cve/CVE-2021-3984</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)</a>
          <a href="https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a">https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3984">https://nvd.nist.gov/vuln/detail/CVE-2021-3984</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-4019</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4019">https://access.redhat.com/security/cve/CVE-2021-4019</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)</a>
          <a href="https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92">https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4019">https://nvd.nist.gov/vuln/detail/CVE-2021-4019</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-4069</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4069">https://access.redhat.com/security/cve/CVE-2021-4069</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069</a>
          <a href="https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9">https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9</a>
          <a href="https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74">https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4069">https://nvd.nist.gov/vuln/detail/CVE-2021-4069</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2021-4166</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4166">https://access.redhat.com/security/cve/CVE-2021-4166</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)</a>
          <a href="https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035">https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4166">https://nvd.nist.gov/vuln/detail/CVE-2021-4166</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2022-0351</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0351">https://access.redhat.com/security/cve/CVE-2022-0351</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)</a>
          <a href="https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161">https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2022-0359</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0359">https://access.redhat.com/security/cve/CVE-2022-0359</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)</a>
          <a href="https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def">https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2022-0361</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)</a>
          <a href="https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b">https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim</td>
        <td>CVE-2022-0368</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0368">https://access.redhat.com/security/cve/CVE-2022-0368</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-3778</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3778">https://access.redhat.com/security/cve/CVE-2021-3778</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778</a>
          <a href="https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f">https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f</a>
          <a href="https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273">https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3778.html">https://linux.oracle.com/cve/CVE-2021-3778.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3778">https://nvd.nist.gov/vuln/detail/CVE-2021-3778</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-3796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3796">https://access.redhat.com/security/cve/CVE-2021-3796</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796</a>
          <a href="https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3">https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3</a>
          <a href="https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d">https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3796.html">https://linux.oracle.com/cve/CVE-2021-3796.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3796">https://nvd.nist.gov/vuln/detail/CVE-2021-3796</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-3927</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3927">https://access.redhat.com/security/cve/CVE-2021-3927</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927</a>
          <a href="https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e">https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e</a>
          <a href="https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0">https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3927">https://nvd.nist.gov/vuln/detail/CVE-2021-3927</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-3928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3928">https://access.redhat.com/security/cve/CVE-2021-3928</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928</a>
          <a href="https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732">https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732</a>
          <a href="https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd">https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3928">https://nvd.nist.gov/vuln/detail/CVE-2021-3928</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-3984</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3984">https://access.redhat.com/security/cve/CVE-2021-3984</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)</a>
          <a href="https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a">https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3984">https://nvd.nist.gov/vuln/detail/CVE-2021-3984</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-4019</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4019">https://access.redhat.com/security/cve/CVE-2021-4019</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)</a>
          <a href="https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92">https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4019">https://nvd.nist.gov/vuln/detail/CVE-2021-4019</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-4069</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4069">https://access.redhat.com/security/cve/CVE-2021-4069</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069</a>
          <a href="https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9">https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9</a>
          <a href="https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74">https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4069">https://nvd.nist.gov/vuln/detail/CVE-2021-4069</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2021-4166</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4166">https://access.redhat.com/security/cve/CVE-2021-4166</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)</a>
          <a href="https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035">https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4166">https://nvd.nist.gov/vuln/detail/CVE-2021-4166</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2022-0351</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0351">https://access.redhat.com/security/cve/CVE-2022-0351</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)</a>
          <a href="https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161">https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2022-0359</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0359">https://access.redhat.com/security/cve/CVE-2022-0359</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)</a>
          <a href="https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def">https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2022-0361</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)</a>
          <a href="https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b">https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-common</td>
        <td>CVE-2022-0368</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0368">https://access.redhat.com/security/cve/CVE-2022-0368</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-3778</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3778">https://access.redhat.com/security/cve/CVE-2021-3778</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778</a>
          <a href="https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f">https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f</a>
          <a href="https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273">https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3778.html">https://linux.oracle.com/cve/CVE-2021-3778.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3778">https://nvd.nist.gov/vuln/detail/CVE-2021-3778</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-3796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3796">https://access.redhat.com/security/cve/CVE-2021-3796</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796</a>
          <a href="https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3">https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3</a>
          <a href="https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d">https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3796.html">https://linux.oracle.com/cve/CVE-2021-3796.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3796">https://nvd.nist.gov/vuln/detail/CVE-2021-3796</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-3927</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3927">https://access.redhat.com/security/cve/CVE-2021-3927</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927</a>
          <a href="https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e">https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e</a>
          <a href="https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0">https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3927">https://nvd.nist.gov/vuln/detail/CVE-2021-3927</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-3928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3928">https://access.redhat.com/security/cve/CVE-2021-3928</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928</a>
          <a href="https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732">https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732</a>
          <a href="https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd">https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3928">https://nvd.nist.gov/vuln/detail/CVE-2021-3928</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-3984</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3984">https://access.redhat.com/security/cve/CVE-2021-3984</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)</a>
          <a href="https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a">https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3984">https://nvd.nist.gov/vuln/detail/CVE-2021-3984</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-4019</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4019">https://access.redhat.com/security/cve/CVE-2021-4019</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)</a>
          <a href="https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92">https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4019">https://nvd.nist.gov/vuln/detail/CVE-2021-4019</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-4069</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4069">https://access.redhat.com/security/cve/CVE-2021-4069</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069</a>
          <a href="https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9">https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9</a>
          <a href="https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74">https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4069">https://nvd.nist.gov/vuln/detail/CVE-2021-4069</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2021-4166</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4166">https://access.redhat.com/security/cve/CVE-2021-4166</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)</a>
          <a href="https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035">https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4166">https://nvd.nist.gov/vuln/detail/CVE-2021-4166</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2022-0351</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0351">https://access.redhat.com/security/cve/CVE-2022-0351</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)</a>
          <a href="https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161">https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2022-0359</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0359">https://access.redhat.com/security/cve/CVE-2022-0359</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)</a>
          <a href="https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def">https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2022-0361</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)</a>
          <a href="https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b">https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-runtime</td>
        <td>CVE-2022-0368</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0368">https://access.redhat.com/security/cve/CVE-2022-0368</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-3778</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3778">https://access.redhat.com/security/cve/CVE-2021-3778</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778</a>
          <a href="https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f">https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f</a>
          <a href="https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273">https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3778.html">https://linux.oracle.com/cve/CVE-2021-3778.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3778">https://nvd.nist.gov/vuln/detail/CVE-2021-3778</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-3796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3796">https://access.redhat.com/security/cve/CVE-2021-3796</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796</a>
          <a href="https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3">https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3</a>
          <a href="https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d">https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3796.html">https://linux.oracle.com/cve/CVE-2021-3796.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3796">https://nvd.nist.gov/vuln/detail/CVE-2021-3796</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-3927</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3927">https://access.redhat.com/security/cve/CVE-2021-3927</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927</a>
          <a href="https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e">https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e</a>
          <a href="https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0">https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3927">https://nvd.nist.gov/vuln/detail/CVE-2021-3927</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-3928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3928">https://access.redhat.com/security/cve/CVE-2021-3928</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928</a>
          <a href="https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732">https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732</a>
          <a href="https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd">https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3928">https://nvd.nist.gov/vuln/detail/CVE-2021-3928</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-3984</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3984">https://access.redhat.com/security/cve/CVE-2021-3984</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)</a>
          <a href="https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a">https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3984">https://nvd.nist.gov/vuln/detail/CVE-2021-3984</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-4019</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4019">https://access.redhat.com/security/cve/CVE-2021-4019</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)</a>
          <a href="https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92">https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4019">https://nvd.nist.gov/vuln/detail/CVE-2021-4019</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-4069</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4069">https://access.redhat.com/security/cve/CVE-2021-4069</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069</a>
          <a href="https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9">https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9</a>
          <a href="https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74">https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4069">https://nvd.nist.gov/vuln/detail/CVE-2021-4069</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2021-4166</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4166">https://access.redhat.com/security/cve/CVE-2021-4166</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)</a>
          <a href="https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035">https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4166">https://nvd.nist.gov/vuln/detail/CVE-2021-4166</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2022-0351</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0351">https://access.redhat.com/security/cve/CVE-2022-0351</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)</a>
          <a href="https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161">https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2022-0359</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0359">https://access.redhat.com/security/cve/CVE-2022-0359</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)</a>
          <a href="https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def">https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2022-0361</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)</a>
          <a href="https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b">https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">vim-tiny</td>
        <td>CVE-2022-0368</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0368">https://access.redhat.com/security/cve/CVE-2022-0368</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">wget</td>
        <td>CVE-2021-31879</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.19.4-1ubuntu2.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-31879">https://access.redhat.com/security/cve/CVE-2021-31879</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31879">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31879</a>
          <a href="https://mail.gnu.org/archive/html/bug-wget/2021-02/msg00002.html">https://mail.gnu.org/archive/html/bug-wget/2021-02/msg00002.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-31879">https://nvd.nist.gov/vuln/detail/CVE-2021-31879</a>
          <a href="https://savannah.gnu.org/bugs/?56909">https://savannah.gnu.org/bugs/?56909</a>
          <a href="https://security.netapp.com/advisory/ntap-20210618-0002/">https://security.netapp.com/advisory/ntap-20210618-0002/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-3778</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3778">https://access.redhat.com/security/cve/CVE-2021-3778</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3778</a>
          <a href="https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f">https://github.com/vim/vim/commit/65b605665997fad54ef39a93199e305af2fe4d7f</a>
          <a href="https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273">https://huntr.dev/bounties/d9c17308-2c99-4f9f-a706-f7f72c24c273</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3778.html">https://linux.oracle.com/cve/CVE-2021-3778.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3778">https://nvd.nist.gov/vuln/detail/CVE-2021-3778</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-3796</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.6</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/10/01/1">http://www.openwall.com/lists/oss-security/2021/10/01/1</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3778.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-3796.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3796">https://access.redhat.com/security/cve/CVE-2021-3796</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3796</a>
          <a href="https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3">https://github.com/vim/vim/commit/35a9a00afcb20897d462a766793ff45534810dc3</a>
          <a href="https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d">https://huntr.dev/bounties/ab60b7f3-6fb1-4ac2-a4fa-4d592e08008d</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3796.html">https://linux.oracle.com/cve/CVE-2021-3796.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4517.html">https://linux.oracle.com/errata/ELSA-2021-4517.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7K4JJBIH3OQSZRVTWKCJCDLGMFGQ5DOH/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S42L4Z4DTW4LHLQ4FJ33VEOXRCBE7WN4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TE62UMYBZE4AE53K6OBBWK32XQ7544QM/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3796">https://nvd.nist.gov/vuln/detail/CVE-2021-3796</a>
          <a href="https://ubuntu.com/security/notices/USN-5093-1">https://ubuntu.com/security/notices/USN-5093-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-3927</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3927">https://access.redhat.com/security/cve/CVE-2021-3927</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3927</a>
          <a href="https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e">https://github.com/vim/vim/commit/0b5b06cb4777d1401fdf83e7d48d287662236e7e</a>
          <a href="https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0">https://huntr.dev/bounties/9c2b2c82-48bb-4be9-ab8f-a48ea252d1b0</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3927">https://nvd.nist.gov/vuln/detail/CVE-2021-3927</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-3928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.7</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3928">https://access.redhat.com/security/cve/CVE-2021-3928</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3928</a>
          <a href="https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732">https://github.com/vim/vim/commit/15d9890eee53afc61eb0a03b878a19cb5672f732</a>
          <a href="https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd">https://huntr.dev/bounties/29c3ebd2-d601-481c-bf96-76975369d0cd</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BCQWPEY2AEYBELCMJYHYWYCD3PZVD2H7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PGW56Z6IN4UVM3E5RXXF4G7LGGTRBI5C/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3928">https://nvd.nist.gov/vuln/detail/CVE-2021-3928</a>
          <a href="https://ubuntu.com/security/notices/USN-5147-1">https://ubuntu.com/security/notices/USN-5147-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-3984</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3984">https://access.redhat.com/security/cve/CVE-2021-3984</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3984</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655</a>
          <a href="https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)">https://github.com/vim/vim/commit/2de9b7c7c8791da8853a9a7ca9c467867465b655 (v8.2.3625)</a>
          <a href="https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a">https://huntr.dev/bounties/b114b5a2-18e2-49f0-b350-15994d71426a</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3984">https://nvd.nist.gov/vuln/detail/CVE-2021-3984</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-4019</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4019">https://access.redhat.com/security/cve/CVE-2021-4019</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142</a>
          <a href="https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)">https://github.com/vim/vim/commit/bd228fd097b41a798f90944b5d1245eddd484142 (v8.2.3669)</a>
          <a href="https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92">https://huntr.dev/bounties/d8798584-a6c9-4619-b18f-001b9a6fca92</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DRPAI5JVZLI7WHWSBR6NWAPBQAYUQREW/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4019">https://nvd.nist.gov/vuln/detail/CVE-2021-4019</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-4069</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td>2:8.0.1453-1ubuntu1.8</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4069">https://access.redhat.com/security/cve/CVE-2021-4069</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069</a>
          <a href="https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9">https://github.com/vim/vim/commit/e031fe90cf2e375ce861ff5e5e281e4ad229ebb9</a>
          <a href="https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74">https://huntr.dev/bounties/0efd6d23-2259-4081-9ff1-3ade26907d74</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNXY7T5OORA7UJIMGSJBGHFMU6UZWS6P/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYB2LLNUFJUKJJ5HYCZ6MV3Z6YX3U5BN/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4069">https://nvd.nist.gov/vuln/detail/CVE-2021-4069</a>
          <a href="https://ubuntu.com/security/notices/USN-5247-1">https://ubuntu.com/security/notices/USN-5247-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2021-4166</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/15/1">http://www.openwall.com/lists/oss-security/2022/01/15/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-4166">https://access.redhat.com/security/cve/CVE-2021-4166</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682</a>
          <a href="https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)">https://github.com/vim/vim/commit/6f98371532fcff911b462d51bc64f2ce8a6ae682 (v8.2.3884)</a>
          <a href="https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035">https://huntr.dev/bounties/229df5dd-5507-44e9-832c-c70364bdf035</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2EY2VFBU3YGGWI5BW4XKT3F37MYGEQUD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3FH2J57GDA2WMBS6J56F6QQRA6BXQQFZ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-4166">https://nvd.nist.gov/vuln/detail/CVE-2021-4166</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2022-0351</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0351">https://access.redhat.com/security/cve/CVE-2022-0351</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0351</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d</a>
          <a href="https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)">https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d (v8.2.4206)</a>
          <a href="https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161">https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2022-0359</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0359">https://access.redhat.com/security/cve/CVE-2022-0359</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0359</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1</a>
          <a href="https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)">https://github.com/vim/vim/commit/85b6747abc15a7a81086db31289cf1b8b17e6cb1 (v8.2.4214)</a>
          <a href="https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def">https://huntr.dev/bounties/a3192d90-4f82-4a67-b7a6-37046cc88def</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2022-0361</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0361</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366</a>
          <a href="https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)">https://github.com/vim/vim/commit/dc5490e2cbc8c16022a23b449b48c1bd0083f366 (v8.2.4215)</a>
          <a href="https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b">https://huntr.dev/bounties/a055618c-0311-409c-a78a-99477121965b</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">xxd</td>
        <td>CVE-2022-0368</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2:8.0.1453-1ubuntu1.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-0368">https://access.redhat.com/security/cve/CVE-2022-0368</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0368</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa</a>
          <a href="https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)">https://github.com/vim/vim/commit/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa (v8.2.4217)</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9</a>
          <a href="https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/">https://huntr.dev/bounties/bca9ce1f-400a-4bf9-9207-3f3187cb3fa9/</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">node-pkg</th></tr>
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">python-pkg</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2020-24583</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.16, 3.0.10, 3.1.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-24583">https://access.redhat.com/security/cve/CVE-2020-24583</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24583">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24583</a>
          <a href="https://docs.djangoproject.com/en/dev/releases/security/">https://docs.djangoproject.com/en/dev/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-m6gj-h9gm-gw44">https://github.com/advisories/GHSA-m6gj-h9gm-gw44</a>
          <a href="https://github.com/django/django/commit/8d7271578d7b153435b40fe40236ebec43cbf1b9">https://github.com/django/django/commit/8d7271578d7b153435b40fe40236ebec43cbf1b9</a>
          <a href="https://groups.google.com/forum/#!topic/django-announce/Gdqn58RqIDM">https://groups.google.com/forum/#!topic/django-announce/Gdqn58RqIDM</a>
          <a href="https://groups.google.com/forum/#!topic/django-announce/zFCMdgUnutU">https://groups.google.com/forum/#!topic/django-announce/zFCMdgUnutU</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/F2ZHO3GZCJMP3DDTXCNVFV6ED3W64NAU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/F2ZHO3GZCJMP3DDTXCNVFV6ED3W64NAU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OLGFFLMF3X6USMJD7V5F5P4K2WVUTO3T/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OLGFFLMF3X6USMJD7V5F5P4K2WVUTO3T/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZCRPQCBTV3RZHKVZ6K6QOAANPRZQD3GI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZCRPQCBTV3RZHKVZ6K6QOAANPRZQD3GI/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-24583">https://nvd.nist.gov/vuln/detail/CVE-2020-24583</a>
          <a href="https://security.netapp.com/advisory/ntap-20200918-0004/">https://security.netapp.com/advisory/ntap-20200918-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-4479-1">https://ubuntu.com/security/notices/USN-4479-1</a>
          <a href="https://usn.ubuntu.com/4479-1/">https://usn.ubuntu.com/4479-1/</a>
          <a href="https://www.djangoproject.com/weblog/2020/sep/01/security-releases/">https://www.djangoproject.com/weblog/2020/sep/01/security-releases/</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/09/01/2">https://www.openwall.com/lists/oss-security/2020/09/01/2</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2020-24584</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.16, 3.0.10, 3.1.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-24584">https://access.redhat.com/security/cve/CVE-2020-24584</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24584">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-24584</a>
          <a href="https://docs.djangoproject.com/en/dev/releases/security/">https://docs.djangoproject.com/en/dev/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-fr28-569j-53c4">https://github.com/advisories/GHSA-fr28-569j-53c4</a>
          <a href="https://github.com/django/django/commit/1853724acaf17ed7414d54c7d2b5563a25025a71">https://github.com/django/django/commit/1853724acaf17ed7414d54c7d2b5563a25025a71</a>
          <a href="https://groups.google.com/forum/#!topic/django-announce/Gdqn58RqIDM">https://groups.google.com/forum/#!topic/django-announce/Gdqn58RqIDM</a>
          <a href="https://groups.google.com/forum/#!topic/django-announce/zFCMdgUnutU">https://groups.google.com/forum/#!topic/django-announce/zFCMdgUnutU</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/F2ZHO3GZCJMP3DDTXCNVFV6ED3W64NAU/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/F2ZHO3GZCJMP3DDTXCNVFV6ED3W64NAU/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OLGFFLMF3X6USMJD7V5F5P4K2WVUTO3T/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OLGFFLMF3X6USMJD7V5F5P4K2WVUTO3T/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZCRPQCBTV3RZHKVZ6K6QOAANPRZQD3GI/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZCRPQCBTV3RZHKVZ6K6QOAANPRZQD3GI/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-24584">https://nvd.nist.gov/vuln/detail/CVE-2020-24584</a>
          <a href="https://security.netapp.com/advisory/ntap-20200918-0004/">https://security.netapp.com/advisory/ntap-20200918-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-4479-1">https://ubuntu.com/security/notices/USN-4479-1</a>
          <a href="https://usn.ubuntu.com/4479-1/">https://usn.ubuntu.com/4479-1/</a>
          <a href="https://www.djangoproject.com/weblog/2020/sep/01/security-releases">https://www.djangoproject.com/weblog/2020/sep/01/security-releases</a>
          <a href="https://www.djangoproject.com/weblog/2020/sep/01/security-releases/">https://www.djangoproject.com/weblog/2020/sep/01/security-releases/</a>
          <a href="https://www.openwall.com/lists/oss-security/2020/09/01/2">https://www.openwall.com/lists/oss-security/2020/09/01/2</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-31542</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.21, 3.1.9, 3.2.1</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/04/3">http://www.openwall.com/lists/oss-security/2021/05/04/3</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-31542">https://access.redhat.com/security/cve/CVE-2021-31542</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31542">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31542</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-rxjp-mfm9-w4wr">https://github.com/advisories/GHSA-rxjp-mfm9-w4wr</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/05/msg00005.html">https://lists.debian.org/debian-lts-announce/2021/05/msg00005.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-31542">https://nvd.nist.gov/vuln/detail/CVE-2021-31542</a>
          <a href="https://security.netapp.com/advisory/ntap-20210618-0001/">https://security.netapp.com/advisory/ntap-20210618-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4932-1">https://ubuntu.com/security/notices/USN-4932-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4932-2">https://ubuntu.com/security/notices/USN-4932-2</a>
          <a href="https://www.djangoproject.com/weblog/2021/may/04/security-releases/">https://www.djangoproject.com/weblog/2021/may/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-33571</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.24, 3.1.12, 3.2.4</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33571">https://access.redhat.com/security/cve/CVE-2021-33571</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33571">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33571</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-p99v-5w3c-jqq9">https://github.com/advisories/GHSA-p99v-5w3c-jqq9</a>
          <a href="https://groups.google.com/g/django-announce/c/sPyjSKMi8Eo">https://groups.google.com/g/django-announce/c/sPyjSKMi8Eo</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33571">https://nvd.nist.gov/vuln/detail/CVE-2021-33571</a>
          <a href="https://security.netapp.com/advisory/ntap-20210727-0004/">https://security.netapp.com/advisory/ntap-20210727-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-4975-1">https://ubuntu.com/security/notices/USN-4975-1</a>
          <a href="https://www.djangoproject.com/weblog/2021/jun/02/security-releases/">https://www.djangoproject.com/weblog/2021/jun/02/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-44420</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.25, 3.1.14, 3.2.10</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-44420">https://access.redhat.com/security/cve/CVE-2021-44420</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44420">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44420</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-v6rh-hp5x-86rv">https://github.com/advisories/GHSA-v6rh-hp5x-86rv</a>
          <a href="https://github.com/django/django/commit/d4dcd5b9dd9e462fec8220e33e3e6c822b7e88a6">https://github.com/django/django/commit/d4dcd5b9dd9e462fec8220e33e3e6c822b7e88a6</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44420">https://nvd.nist.gov/vuln/detail/CVE-2021-44420</a>
          <a href="https://security.netapp.com/advisory/ntap-20211229-0006/">https://security.netapp.com/advisory/ntap-20211229-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-5178-1">https://ubuntu.com/security/notices/USN-5178-1</a>
          <a href="https://www.djangoproject.com/weblog/2021/dec/07/security-releases/">https://www.djangoproject.com/weblog/2021/dec/07/security-releases/</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/12/07/1">https://www.openwall.com/lists/oss-security/2021/12/07/1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45115</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45115">https://access.redhat.com/security/cve/CVE-2021-45115</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45115">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45115</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-53qw-q765-4fww">https://github.com/advisories/GHSA-53qw-q765-4fww</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45115">https://nvd.nist.gov/vuln/detail/CVE-2021-45115</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45116</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45116">https://access.redhat.com/security/cve/CVE-2021-45116</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45116">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45116</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-8c5j-9r9f-c6w8">https://github.com/advisories/GHSA-8c5j-9r9f-c6w8</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45116">https://nvd.nist.gov/vuln/detail/CVE-2021-45116</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-28658</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.20, 3.0.14, 3.1.8</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-28658">https://access.redhat.com/security/cve/CVE-2021-28658</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28658">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28658</a>
          <a href="https://docs.djangoproject.com/en/3.1/releases/security/">https://docs.djangoproject.com/en/3.1/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-xgxc-v2qg-chmh">https://github.com/advisories/GHSA-xgxc-v2qg-chmh</a>
          <a href="https://groups.google.com/g/django-announce/c/ePr5j-ngdPU">https://groups.google.com/g/django-announce/c/ePr5j-ngdPU</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/04/msg00008.html">https://lists.debian.org/debian-lts-announce/2021/04/msg00008.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28658">https://nvd.nist.gov/vuln/detail/CVE-2021-28658</a>
          <a href="https://pypi.org/project/Django/">https://pypi.org/project/Django/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210528-0001/">https://security.netapp.com/advisory/ntap-20210528-0001/</a>
          <a href="https://ubuntu.com/security/notices/USN-4902-1">https://ubuntu.com/security/notices/USN-4902-1</a>
          <a href="https://www.djangoproject.com/weblog/2021/apr/06/security-releases/">https://www.djangoproject.com/weblog/2021/apr/06/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-32052</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.22, 3.1.10, 3.2.2</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/05/06/1">http://www.openwall.com/lists/oss-security/2021/05/06/1</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-32052">https://access.redhat.com/security/cve/CVE-2021-32052</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1944801">https://bugzilla.redhat.com/show_bug.cgi?id=1944801</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32052">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32052</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-qm57-vhq3-3fwf">https://github.com/advisories/GHSA-qm57-vhq3-3fwf</a>
          <a href="https://github.com/django/django/commit/e1e81aa1c4427411e3c68facdd761229ffea6f6f">https://github.com/django/django/commit/e1e81aa1c4427411e3c68facdd761229ffea6f6f</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-32052">https://nvd.nist.gov/vuln/detail/CVE-2021-32052</a>
          <a href="https://security.netapp.com/advisory/ntap-20210611-0002/">https://security.netapp.com/advisory/ntap-20210611-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-4975-1">https://ubuntu.com/security/notices/USN-4975-1</a>
          <a href="https://www.djangoproject.com/weblog/2021/may/06/security-releases/">https://www.djangoproject.com/weblog/2021/may/06/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-3281</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.18, 3.0.12, 3.1.6</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-3281">https://access.redhat.com/security/cve/CVE-2021-3281</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3281">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3281</a>
          <a href="https://docs.djangoproject.com/en/3.1/releases/3.0.12/">https://docs.djangoproject.com/en/3.1/releases/3.0.12/</a>
          <a href="https://docs.djangoproject.com/en/3.1/releases/security/">https://docs.djangoproject.com/en/3.1/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-fvgf-6h6h-3322">https://github.com/advisories/GHSA-fvgf-6h6h-3322</a>
          <a href="https://github.com/django/django/commit/05413afa8c18cdb978fcdf470e09f7a12b234a23">https://github.com/django/django/commit/05413afa8c18cdb978fcdf470e09f7a12b234a23</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YF52FKEH5S2P5CM4X7IXSYG67YY2CDOO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YF52FKEH5S2P5CM4X7IXSYG67YY2CDOO/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3281">https://nvd.nist.gov/vuln/detail/CVE-2021-3281</a>
          <a href="https://security.netapp.com/advisory/ntap-20210226-0004/">https://security.netapp.com/advisory/ntap-20210226-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-4715-1">https://ubuntu.com/security/notices/USN-4715-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4715-2">https://ubuntu.com/security/notices/USN-4715-2</a>
          <a href="https://www.djangoproject.com/weblog/2021/feb/01/security-releases/">https://www.djangoproject.com/weblog/2021/feb/01/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-33203</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.24, 3.1.12, 3.2.4</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33203">https://access.redhat.com/security/cve/CVE-2021-33203</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33203">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33203</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-68w8-qjq3-2gfm">https://github.com/advisories/GHSA-68w8-qjq3-2gfm</a>
          <a href="https://github.com/django/django/commit/053cc9534d174dc89daba36724ed2dcb36755b90">https://github.com/django/django/commit/053cc9534d174dc89daba36724ed2dcb36755b90</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33203">https://nvd.nist.gov/vuln/detail/CVE-2021-33203</a>
          <a href="https://security.netapp.com/advisory/ntap-20210727-0004/">https://security.netapp.com/advisory/ntap-20210727-0004/</a>
          <a href="https://ubuntu.com/security/notices/USN-4975-1">https://ubuntu.com/security/notices/USN-4975-1</a>
          <a href="https://ubuntu.com/security/notices/USN-4975-2">https://ubuntu.com/security/notices/USN-4975-2</a>
          <a href="https://www.djangoproject.com/weblog/2021/jun/02/security-releases/">https://www.djangoproject.com/weblog/2021/jun/02/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45452</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.14</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45452">https://access.redhat.com/security/cve/CVE-2021-45452</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45452">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45452</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-jrh2-hc4r-7jwx">https://github.com/advisories/GHSA-jrh2-hc4r-7jwx</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45452">https://nvd.nist.gov/vuln/detail/CVE-2021-45452</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-44420</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.24</td>
        <td>2.2.25, 3.1.14, 3.2.10</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-44420">https://access.redhat.com/security/cve/CVE-2021-44420</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44420">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44420</a>
          <a href="https://docs.djangoproject.com/en/3.2/releases/security/">https://docs.djangoproject.com/en/3.2/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-v6rh-hp5x-86rv">https://github.com/advisories/GHSA-v6rh-hp5x-86rv</a>
          <a href="https://github.com/django/django/commit/d4dcd5b9dd9e462fec8220e33e3e6c822b7e88a6">https://github.com/django/django/commit/d4dcd5b9dd9e462fec8220e33e3e6c822b7e88a6</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44420">https://nvd.nist.gov/vuln/detail/CVE-2021-44420</a>
          <a href="https://security.netapp.com/advisory/ntap-20211229-0006/">https://security.netapp.com/advisory/ntap-20211229-0006/</a>
          <a href="https://ubuntu.com/security/notices/USN-5178-1">https://ubuntu.com/security/notices/USN-5178-1</a>
          <a href="https://www.djangoproject.com/weblog/2021/dec/07/security-releases/">https://www.djangoproject.com/weblog/2021/dec/07/security-releases/</a>
          <a href="https://www.openwall.com/lists/oss-security/2021/12/07/1">https://www.openwall.com/lists/oss-security/2021/12/07/1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45115</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.24</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45115">https://access.redhat.com/security/cve/CVE-2021-45115</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45115">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45115</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-53qw-q765-4fww">https://github.com/advisories/GHSA-53qw-q765-4fww</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45115">https://nvd.nist.gov/vuln/detail/CVE-2021-45115</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45116</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.2.24</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45116">https://access.redhat.com/security/cve/CVE-2021-45116</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45116">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45116</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-8c5j-9r9f-c6w8">https://github.com/advisories/GHSA-8c5j-9r9f-c6w8</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45116">https://nvd.nist.gov/vuln/detail/CVE-2021-45116</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">Django</td>
        <td>CVE-2021-45452</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.2.24</td>
        <td>2.2.26, 3.2.11, 4.0.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-45452">https://access.redhat.com/security/cve/CVE-2021-45452</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45452">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45452</a>
          <a href="https://docs.djangoproject.com/en/4.0/releases/security/">https://docs.djangoproject.com/en/4.0/releases/security/</a>
          <a href="https://github.com/advisories/GHSA-jrh2-hc4r-7jwx">https://github.com/advisories/GHSA-jrh2-hc4r-7jwx</a>
          <a href="https://groups.google.com/forum/#!forum/django-announce">https://groups.google.com/forum/#!forum/django-announce</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-45452">https://nvd.nist.gov/vuln/detail/CVE-2021-45452</a>
          <a href="https://security.netapp.com/advisory/ntap-20220121-0005/">https://security.netapp.com/advisory/ntap-20220121-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5204-1">https://ubuntu.com/security/notices/USN-5204-1</a>
          <a href="https://www.djangoproject.com/weblog/2022/jan/04/security-releases/">https://www.djangoproject.com/weblog/2022/jan/04/security-releases/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">Pillow</td>
        <td>CVE-2021-34552</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">8.2.0</td>
        <td>8.3.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-34552.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-34552.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-34552">https://access.redhat.com/security/cve/CVE-2021-34552</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34552">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34552</a>
          <a href="https://github.com/advisories/GHSA-7534-mm45-c74v">https://github.com/advisories/GHSA-7534-mm45-c74v</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/07/msg00018.html">https://lists.debian.org/debian-lts-announce/2021/07/msg00018.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7V6LCG525ARIX6LX5QRYNAWVDD2MD2SV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7V6LCG525ARIX6LX5QRYNAWVDD2MD2SV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VUGBBT63VL7G4JNOEIPDJIOC34ZFBKNJ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VUGBBT63VL7G4JNOEIPDJIOC34ZFBKNJ/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-34552">https://nvd.nist.gov/vuln/detail/CVE-2021-34552</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/8.3.0.html#buffer-overflow">https://pillow.readthedocs.io/en/stable/releasenotes/8.3.0.html#buffer-overflow</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/index.html">https://pillow.readthedocs.io/en/stable/releasenotes/index.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-1">https://ubuntu.com/security/notices/USN-5227-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-2">https://ubuntu.com/security/notices/USN-5227-2</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">Pillow</td>
        <td>CVE-2022-22815</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">8.2.0</td>
        <td>9.0.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-22815">https://access.redhat.com/security/cve/CVE-2022-22815</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22815">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22815</a>
          <a href="https://github.com/advisories/GHSA-pw3c-h7wp-cvhx">https://github.com/advisories/GHSA-pw3c-h7wp-cvhx</a>
          <a href="https://github.com/python-pillow/Pillow/blob/c5d9223a8b5e9295d15b5a9b1ef1dae44c8499f3/src/path.c#L331">https://github.com/python-pillow/Pillow/blob/c5d9223a8b5e9295d15b5a9b1ef1dae44c8499f3/src/path.c#L331</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22815">https://nvd.nist.gov/vuln/detail/CVE-2022-22815</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling">https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-1">https://ubuntu.com/security/notices/USN-5227-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-2">https://ubuntu.com/security/notices/USN-5227-2</a>
          <a href="https://www.debian.org/security/2022/dsa-5053">https://www.debian.org/security/2022/dsa-5053</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">Pillow</td>
        <td>CVE-2022-22816</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">8.2.0</td>
        <td>9.0.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-22816">https://access.redhat.com/security/cve/CVE-2022-22816</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22816">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22816</a>
          <a href="https://github.com/advisories/GHSA-xrcv-f9gm-v42c">https://github.com/advisories/GHSA-xrcv-f9gm-v42c</a>
          <a href="https://github.com/python-pillow/Pillow/blob/c5d9223a8b5e9295d15b5a9b1ef1dae44c8499f3/src/path.c#L331">https://github.com/python-pillow/Pillow/blob/c5d9223a8b5e9295d15b5a9b1ef1dae44c8499f3/src/path.c#L331</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22816">https://nvd.nist.gov/vuln/detail/CVE-2022-22816</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling">https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#fixed-imagepath-path-array-handling</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-1">https://ubuntu.com/security/notices/USN-5227-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-2">https://ubuntu.com/security/notices/USN-5227-2</a>
          <a href="https://www.debian.org/security/2022/dsa-5053">https://www.debian.org/security/2022/dsa-5053</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">Pillow</td>
        <td>CVE-2022-22817</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">8.2.0</td>
        <td>9.0.0</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-22817">https://access.redhat.com/security/cve/CVE-2022-22817</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22817">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22817</a>
          <a href="https://github.com/advisories/GHSA-8vj2-vxx3-667w">https://github.com/advisories/GHSA-8vj2-vxx3-667w</a>
          <a href="https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html">https://lists.debian.org/debian-lts-announce/2022/01/msg00018.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22817">https://nvd.nist.gov/vuln/detail/CVE-2022-22817</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#restrict-builtins-available-to-imagemath-eval">https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#restrict-builtins-available-to-imagemath-eval</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-1">https://ubuntu.com/security/notices/USN-5227-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-2">https://ubuntu.com/security/notices/USN-5227-2</a>
          <a href="https://www.debian.org/security/2022/dsa-5053">https://www.debian.org/security/2022/dsa-5053</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">Pillow</td>
        <td>CVE-2021-23437</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">8.2.0</td>
        <td>8.3.2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-23437">https://access.redhat.com/security/cve/CVE-2021-23437</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23437">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23437</a>
          <a href="https://github.com/advisories/GHSA-98vv-pw6r-q6q4">https://github.com/advisories/GHSA-98vv-pw6r-q6q4</a>
          <a href="https://github.com/python-pillow/Pillow/commit/9e08eb8f78fdfd2f476e1b20b7cf38683754866b">https://github.com/python-pillow/Pillow/commit/9e08eb8f78fdfd2f476e1b20b7cf38683754866b</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNSG6VFXTAROGF7ACYLMAZNQV4EJ6I2C/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RNSG6VFXTAROGF7ACYLMAZNQV4EJ6I2C/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VKRCL7KKAKOXCVD7M6WC5OKFGL4L3SJT/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VKRCL7KKAKOXCVD7M6WC5OKFGL4L3SJT/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23437">https://nvd.nist.gov/vuln/detail/CVE-2021-23437</a>
          <a href="https://pillow.readthedocs.io/en/stable/releasenotes/8.3.2.html">https://pillow.readthedocs.io/en/stable/releasenotes/8.3.2.html</a>
          <a href="https://snyk.io/vuln/SNYK-PYTHON-PILLOW-1319443">https://snyk.io/vuln/SNYK-PYTHON-PILLOW-1319443</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-1">https://ubuntu.com/security/notices/USN-5227-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5227-2">https://ubuntu.com/security/notices/USN-5227-2</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">djangorestframework</td>
        <td>CVE-2020-25626</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.11.1</td>
        <td>3.11.2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25626">https://access.redhat.com/security/cve/CVE-2020-25626</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1878635">https://bugzilla.redhat.com/show_bug.cgi?id=1878635</a>
          <a href="https://github.com/advisories/GHSA-fx83-3ph3-9j2q">https://github.com/advisories/GHSA-fx83-3ph3-9j2q</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-25626">https://nvd.nist.gov/vuln/detail/CVE-2020-25626</a>
          <a href="https://security.netapp.com/advisory/ntap-20201016-0003/">https://security.netapp.com/advisory/ntap-20201016-0003/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">lxml</td>
        <td>CVE-2021-43818</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">4.6.3</td>
        <td>4.6.5</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-43818">https://access.redhat.com/security/cve/CVE-2021-43818</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43818">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43818</a>
          <a href="https://github.com/advisories/GHSA-55x5-fj6c-h6m8">https://github.com/advisories/GHSA-55x5-fj6c-h6m8</a>
          <a href="https://github.com/lxml/lxml/blob/lxml-4.6.5/CHANGES.txt">https://github.com/lxml/lxml/blob/lxml-4.6.5/CHANGES.txt</a>
          <a href="https://github.com/lxml/lxml/commit/12fa9669007180a7bb87d990c375cf91ca5b664a">https://github.com/lxml/lxml/commit/12fa9669007180a7bb87d990c375cf91ca5b664a</a>
          <a href="https://github.com/lxml/lxml/commit/12fa9669007180a7bb87d990c375cf91ca5b664a (lxml-4.6.5)">https://github.com/lxml/lxml/commit/12fa9669007180a7bb87d990c375cf91ca5b664a (lxml-4.6.5)</a>
          <a href="https://github.com/lxml/lxml/commit/a3eacbc0dcf1de1c822ec29fb7d090a4b1712a9c#diff-59130575b4fb2932c957db2922977d7d89afb0b2085357db1a14615a2fcad776">https://github.com/lxml/lxml/commit/a3eacbc0dcf1de1c822ec29fb7d090a4b1712a9c#diff-59130575b4fb2932c957db2922977d7d89afb0b2085357db1a14615a2fcad776</a>
          <a href="https://github.com/lxml/lxml/commit/f2330237440df7e8f39c3ad1b1aa8852be3b27c0">https://github.com/lxml/lxml/commit/f2330237440df7e8f39c3ad1b1aa8852be3b27c0</a>
          <a href="https://github.com/lxml/lxml/commit/f2330237440df7e8f39c3ad1b1aa8852be3b27c0 (lxml-4.6.5)">https://github.com/lxml/lxml/commit/f2330237440df7e8f39c3ad1b1aa8852be3b27c0 (lxml-4.6.5)</a>
          <a href="https://github.com/lxml/lxml/security/advisories/GHSA-55x5-fj6c-h6m8">https://github.com/lxml/lxml/security/advisories/GHSA-55x5-fj6c-h6m8</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/12/msg00037.html">https://lists.debian.org/debian-lts-announce/2021/12/msg00037.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TUIS2KE3HZ2AAQKXFLTJFZPP2IFHJTC7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TUIS2KE3HZ2AAQKXFLTJFZPP2IFHJTC7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/V2XMOM5PFT6U5AAXY6EFNT5JZCKKHK2V/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/V2XMOM5PFT6U5AAXY6EFNT5JZCKKHK2V/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WZGNET2A4WGLSUXLBFYKNC5PXHQMI3I7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WZGNET2A4WGLSUXLBFYKNC5PXHQMI3I7/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4SPKJX3RRJK4UWA6FXCRHD2TVRQI44/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZQ4SPKJX3RRJK4UWA6FXCRHD2TVRQI44/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-43818">https://nvd.nist.gov/vuln/detail/CVE-2021-43818</a>
          <a href="https://security.netapp.com/advisory/ntap-20220107-0005/">https://security.netapp.com/advisory/ntap-20220107-0005/</a>
          <a href="https://ubuntu.com/security/notices/USN-5225-1">https://ubuntu.com/security/notices/USN-5225-1</a>
          <a href="https://www.debian.org/security/2022/dsa-5043">https://www.debian.org/security/2022/dsa-5043</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">sqlparse</td>
        <td>CVE-2021-32839</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">0.4.1</td>
        <td>0.4.2</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-32839">https://access.redhat.com/security/cve/CVE-2021-32839</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32839">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32839</a>
          <a href="https://github.com/advisories/GHSA-p5w8-wqhj-9hhf">https://github.com/advisories/GHSA-p5w8-wqhj-9hhf</a>
          <a href="https://github.com/andialbrecht/sqlparse/commit/8238a9e450ed1524e40cb3a8b0b3c00606903aeb">https://github.com/andialbrecht/sqlparse/commit/8238a9e450ed1524e40cb3a8b0b3c00606903aeb</a>
          <a href="https://github.com/andialbrecht/sqlparse/security/advisories/GHSA-p5w8-wqhj-9hhf">https://github.com/andialbrecht/sqlparse/security/advisories/GHSA-p5w8-wqhj-9hhf</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-32839">https://nvd.nist.gov/vuln/detail/CVE-2021-32839</a>
          <a href="https://securitylab.github.com/advisories/GHSL-2021-107-andialbrecht-sqlparse/">https://securitylab.github.com/advisories/GHSL-2021-107-andialbrecht-sqlparse/</a>
          <a href="https://ubuntu.com/security/notices/USN-5085-1">https://ubuntu.com/security/notices/USN-5085-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">urllib3</td>
        <td>CVE-2021-33503</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.26.4</td>
        <td>1.26.5</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-33503">https://access.redhat.com/security/cve/CVE-2021-33503</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33503">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33503</a>
          <a href="https://github.com/advisories/GHSA-q2q7-5pp4-w6pg">https://github.com/advisories/GHSA-q2q7-5pp4-w6pg</a>
          <a href="https://github.com/urllib3/urllib3/commit/2d4a3fee6de2fa45eb82169361918f759269b4ec">https://github.com/urllib3/urllib3/commit/2d4a3fee6de2fa45eb82169361918f759269b4ec</a>
          <a href="https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg">https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-33503.html">https://linux.oracle.com/cve/CVE-2021-33503.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-4162.html">https://linux.oracle.com/errata/ELSA-2021-4162.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6SCV7ZNAHS3E6PBFLJGENCDRDRWRZZ6W/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6SCV7ZNAHS3E6PBFLJGENCDRDRWRZZ6W/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FMUGWEAUYGGHTPPXT6YBD53WYXQGVV73/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FMUGWEAUYGGHTPPXT6YBD53WYXQGVV73/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-33503">https://nvd.nist.gov/vuln/detail/CVE-2021-33503</a>
          <a href="https://security.gentoo.org/glsa/202107-36">https://security.gentoo.org/glsa/202107-36</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
