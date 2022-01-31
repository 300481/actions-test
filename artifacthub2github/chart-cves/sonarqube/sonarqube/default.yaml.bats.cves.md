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
    <title>bats/bats:1.2.1 (alpine 3.11.3) - Trivy Report - 2022-01-31 19:31:38.166893621 +0000 UTC m=+0.755388567 </title>
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
    <h1>bats/bats:1.2.1 (alpine 3.11.3) - Trivy Report - 2022-01-31 19:31:38.166918921 +0000 UTC m=+0.755413867</h1>
    <table>
      <tr class="group-header"><th colspan="6">alpine</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">apk-tools</td>
        <td>CVE-2021-36159</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">2.10.4-r3</td>
        <td>2.10.7-r0</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/freebsd/freebsd-src/commits/main/lib/libfetch">https://github.com/freebsd/freebsd-src/commits/main/lib/libfetch</a>
          <a href="https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10749">https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10749</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E">https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">apk-tools</td>
        <td>CVE-2021-30139</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">2.10.4-r3</td>
        <td>2.10.6-r0</td>
        <td class="links" data-more-links="off">
          <a href="https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10741">https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10741</a>
          <a href="https://gitlab.alpinelinux.org/alpine/aports/-/issues/12606">https://gitlab.alpinelinux.org/alpine/aports/-/issues/12606</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-28831</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r10</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-28831">https://access.redhat.com/security/cve/CVE-2021-28831</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831</a>
          <a href="https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd">https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html">https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28831">https://nvd.nist.gov/vuln/detail/CVE-2021-28831</a>
          <a href="https://security.gentoo.org/glsa/202105-09">https://security.gentoo.org/glsa/202105-09</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42378</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42378">https://access.redhat.com/security/cve/CVE-2021-42378</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42378">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42378</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42378">https://nvd.nist.gov/vuln/detail/CVE-2021-42378</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42379</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42379">https://access.redhat.com/security/cve/CVE-2021-42379</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42379">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42379</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42379">https://nvd.nist.gov/vuln/detail/CVE-2021-42379</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42380</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42380">https://access.redhat.com/security/cve/CVE-2021-42380</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42380">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42380</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42380">https://nvd.nist.gov/vuln/detail/CVE-2021-42380</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42381</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42381">https://access.redhat.com/security/cve/CVE-2021-42381</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42381">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42381</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42381">https://nvd.nist.gov/vuln/detail/CVE-2021-42381</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42382</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42382">https://access.redhat.com/security/cve/CVE-2021-42382</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42382">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42382</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42382">https://nvd.nist.gov/vuln/detail/CVE-2021-42382</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42383</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42383">https://access.redhat.com/security/cve/CVE-2021-42383</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42384</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42384">https://access.redhat.com/security/cve/CVE-2021-42384</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42384">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42384</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42384">https://nvd.nist.gov/vuln/detail/CVE-2021-42384</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42385</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42385">https://access.redhat.com/security/cve/CVE-2021-42385</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42385">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42385</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42385">https://nvd.nist.gov/vuln/detail/CVE-2021-42385</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42386</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42386">https://access.redhat.com/security/cve/CVE-2021-42386</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42386">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42386</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42386">https://nvd.nist.gov/vuln/detail/CVE-2021-42386</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42374</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42374">https://access.redhat.com/security/cve/CVE-2021-42374</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42374">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42374</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42374">https://nvd.nist.gov/vuln/detail/CVE-2021-42374</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-3711</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1l-r0</td>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2020-1967</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1g-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html">http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html">http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html</a>
          <a href="http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html">http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html</a>
          <a href="http://seclists.org/fulldisclosure/2020/May/5">http://seclists.org/fulldisclosure/2020/May/5</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/04/22/2">http://www.openwall.com/lists/oss-security/2020/04/22/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-1967">https://access.redhat.com/security/cve/CVE-2020-1967</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1967">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1967</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1</a>
          <a href="https://github.com/irsl/CVE-2020-1967">https://github.com/irsl/CVE-2020-1967</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440</a>
          <a href="https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1967">https://nvd.nist.gov/vuln/detail/CVE-2020-1967</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2020-0015.html">https://rustsec.org/advisories/RUSTSEC-2020-0015.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202004-10">https://security.gentoo.org/glsa/202004-10</a>
          <a href="https://security.netapp.com/advisory/ntap-20200424-0003/">https://security.netapp.com/advisory/ntap-20200424-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200717-0004/">https://security.netapp.com/advisory/ntap-20200717-0004/</a>
          <a href="https://www.debian.org/security/2020/dsa-4661">https://www.debian.org/security/2020/dsa-4661</a>
          <a href="https://www.openssl.org/news/secadv/20200421.txt">https://www.openssl.org/news/secadv/20200421.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_20_05">https://www.synology.com/security/advisory/Synology_SA_20_05</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL">https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL</a>
          <a href="https://www.tenable.com/security/tns-2020-03">https://www.tenable.com/security/tns-2020-03</a>
          <a href="https://www.tenable.com/security/tns-2020-04">https://www.tenable.com/security/tns-2020-04</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-23840</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1j-r0</td>
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
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-3450</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1k-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/1">http://www.openwall.com/lists/oss-security/2021/03/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/2">http://www.openwall.com/lists/oss-security/2021/03/27/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/3">http://www.openwall.com/lists/oss-security/2021/03/28/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/4">http://www.openwall.com/lists/oss-security/2021/03/28/4</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3450">https://access.redhat.com/security/cve/CVE-2021-3450</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3450.html">https://linux.oracle.com/cve/CVE-2021-3450.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9151.html">https://linux.oracle.com/errata/ELSA-2021-9151.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/</a>
          <a href="https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html">https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html</a>
          <a href="https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013">https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0056.html">https://rustsec.org/advisories/RUSTSEC-2021-0056.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210326-0006/">https://security.netapp.com/advisory/ntap-20210326-0006/</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd</a>
          <a href="https://www.openssl.org/news/secadv/20210325.txt">https://www.openssl.org/news/secadv/20210325.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-05">https://www.tenable.com/security/tns-2021-05</a>
          <a href="https://www.tenable.com/security/tns-2021-08">https://www.tenable.com/security/tns-2021-08</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1l-r0</td>
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
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2020-1971</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1i-r0</td>
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
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-23841</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1j-r0</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libcrypto1.1</td>
        <td>CVE-2021-3449</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1k-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/1">http://www.openwall.com/lists/oss-security/2021/03/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/2">http://www.openwall.com/lists/oss-security/2021/03/27/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/3">http://www.openwall.com/lists/oss-security/2021/03/28/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/4">http://www.openwall.com/lists/oss-security/2021/03/28/4</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3449">https://access.redhat.com/security/cve/CVE-2021-3449</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3449.html">https://linux.oracle.com/cve/CVE-2021-3449.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9151.html">https://linux.oracle.com/errata/ELSA-2021-9151.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html">https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/</a>
          <a href="https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013">https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0055.html">https://rustsec.org/advisories/RUSTSEC-2021-0055.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210326-0006/">https://security.netapp.com/advisory/ntap-20210326-0006/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd</a>
          <a href="https://ubuntu.com/security/notices/USN-4891-1">https://ubuntu.com/security/notices/USN-4891-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5038-1">https://ubuntu.com/security/notices/USN-5038-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4875">https://www.debian.org/security/2021/dsa-4875</a>
          <a href="https://www.openssl.org/news/secadv/20210325.txt">https://www.openssl.org/news/secadv/20210325.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-05">https://www.tenable.com/security/tns-2021-05</a>
          <a href="https://www.tenable.com/security/tns-2021-06">https://www.tenable.com/security/tns-2021-06</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3711</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1l-r0</td>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2020-1967</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1g-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html">http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00004.html</a>
          <a href="http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html">http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00011.html</a>
          <a href="http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html">http://packetstormsecurity.com/files/157527/OpenSSL-signature_algorithms_cert-Denial-Of-Service.html</a>
          <a href="http://seclists.org/fulldisclosure/2020/May/5">http://seclists.org/fulldisclosure/2020/May/5</a>
          <a href="http://www.openwall.com/lists/oss-security/2020/04/22/2">http://www.openwall.com/lists/oss-security/2020/04/22/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2020-1967">https://access.redhat.com/security/cve/CVE-2020-1967</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1967">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1967</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1</a>
          <a href="https://github.com/irsl/CVE-2020-1967">https://github.com/irsl/CVE-2020-1967</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44440</a>
          <a href="https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r66ea9c436da150683432db5fbc8beb8ae01886c6459ac30c2cea7345@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r94d6ac3f010a38fccf4f432b12180a13fa1cf303559bd805648c9064@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E">https://lists.apache.org/thread.html/r9a41e304992ce6aec6585a87842b4f2e692604f5c892c37e3b0587ee@%3Cdev.tomcat.apache.org%3E</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDHOAATPWJCXRNFMJ2SASDBBNU5RJONY/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EXDDAOWSAIEFQNBHWYE6PPYFV4QXGMCD/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XVEP3LAK4JSPRXFO4QF4GG2IVXADV3SO/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-1967">https://nvd.nist.gov/vuln/detail/CVE-2020-1967</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2020-0015.html">https://rustsec.org/advisories/RUSTSEC-2020-0015.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-20:11.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202004-10">https://security.gentoo.org/glsa/202004-10</a>
          <a href="https://security.netapp.com/advisory/ntap-20200424-0003/">https://security.netapp.com/advisory/ntap-20200424-0003/</a>
          <a href="https://security.netapp.com/advisory/ntap-20200717-0004/">https://security.netapp.com/advisory/ntap-20200717-0004/</a>
          <a href="https://www.debian.org/security/2020/dsa-4661">https://www.debian.org/security/2020/dsa-4661</a>
          <a href="https://www.openssl.org/news/secadv/20200421.txt">https://www.openssl.org/news/secadv/20200421.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujan2021.html">https://www.oracle.com/security-alerts/cpujan2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpujul2020.html">https://www.oracle.com/security-alerts/cpujul2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2020.html">https://www.oracle.com/security-alerts/cpuoct2020.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_20_05">https://www.synology.com/security/advisory/Synology_SA_20_05</a>
          <a href="https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL">https://www.synology.com/security/advisory/Synology_SA_20_05_OpenSSL</a>
          <a href="https://www.tenable.com/security/tns-2020-03">https://www.tenable.com/security/tns-2020-03</a>
          <a href="https://www.tenable.com/security/tns-2020-04">https://www.tenable.com/security/tns-2020-04</a>
          <a href="https://www.tenable.com/security/tns-2020-11">https://www.tenable.com/security/tns-2020-11</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-23840</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1j-r0</td>
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
        <td>CVE-2021-3450</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1k-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/1">http://www.openwall.com/lists/oss-security/2021/03/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/2">http://www.openwall.com/lists/oss-security/2021/03/27/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/3">http://www.openwall.com/lists/oss-security/2021/03/28/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/4">http://www.openwall.com/lists/oss-security/2021/03/28/4</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3450">https://access.redhat.com/security/cve/CVE-2021-3450</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a40b7bc7b94dd7de897a74571e7024f0cf0d63b</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3450.html">https://linux.oracle.com/cve/CVE-2021-3450.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9151.html">https://linux.oracle.com/errata/ELSA-2021-9151.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/</a>
          <a href="https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html">https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html</a>
          <a href="https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013">https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0056.html">https://rustsec.org/advisories/RUSTSEC-2021-0056.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210326-0006/">https://security.netapp.com/advisory/ntap-20210326-0006/</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd</a>
          <a href="https://www.openssl.org/news/secadv/20210325.txt">https://www.openssl.org/news/secadv/20210325.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-05">https://www.tenable.com/security/tns-2021-05</a>
          <a href="https://www.tenable.com/security/tns-2021-08">https://www.tenable.com/security/tns-2021-08</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1l-r0</td>
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
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1i-r0</td>
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
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1j-r0</td>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3449</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.1d-r3</td>
        <td>1.1.1k-r0</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/1">http://www.openwall.com/lists/oss-security/2021/03/27/1</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/27/2">http://www.openwall.com/lists/oss-security/2021/03/27/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/3">http://www.openwall.com/lists/oss-security/2021/03/28/3</a>
          <a href="http://www.openwall.com/lists/oss-security/2021/03/28/4">http://www.openwall.com/lists/oss-security/2021/03/28/4</a>
          <a href="https://access.redhat.com/security/cve/CVE-2021-3449">https://access.redhat.com/security/cve/CVE-2021-3449</a>
          <a href="https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf">https://cert-portal.siemens.com/productcert/pdf/ssa-772220.pdf</a>
          <a href="https://crates.io/crates/openssl-src">https://crates.io/crates/openssl-src</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449</a>
          <a href="https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148">https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fb9fa6b51defd48157eeb207f52181f735d96148</a>
          <a href="https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44845</a>
          <a href="https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356">https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10356</a>
          <a href="https://linux.oracle.com/cve/CVE-2021-3449.html">https://linux.oracle.com/cve/CVE-2021-3449.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9151.html">https://linux.oracle.com/errata/ELSA-2021-9151.html</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html">https://lists.debian.org/debian-lts-announce/2021/08/msg00029.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CCBFLLVQVILIVGZMBJL3IXZGKWQISYNP/</a>
          <a href="https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013">https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0013</a>
          <a href="https://rustsec.org/advisories/RUSTSEC-2021-0055.html">https://rustsec.org/advisories/RUSTSEC-2021-0055.html</a>
          <a href="https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc">https://security.FreeBSD.org/advisories/FreeBSD-SA-21:07.openssl.asc</a>
          <a href="https://security.gentoo.org/glsa/202103-03">https://security.gentoo.org/glsa/202103-03</a>
          <a href="https://security.netapp.com/advisory/ntap-20210326-0006/">https://security.netapp.com/advisory/ntap-20210326-0006/</a>
          <a href="https://security.netapp.com/advisory/ntap-20210513-0002/">https://security.netapp.com/advisory/ntap-20210513-0002/</a>
          <a href="https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-2021-GHY28dJd</a>
          <a href="https://ubuntu.com/security/notices/USN-4891-1">https://ubuntu.com/security/notices/USN-4891-1</a>
          <a href="https://ubuntu.com/security/notices/USN-5038-1">https://ubuntu.com/security/notices/USN-5038-1</a>
          <a href="https://www.debian.org/security/2021/dsa-4875">https://www.debian.org/security/2021/dsa-4875</a>
          <a href="https://www.openssl.org/news/secadv/20210325.txt">https://www.openssl.org/news/secadv/20210325.txt</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuApr2021.html">https://www.oracle.com/security-alerts/cpuApr2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
          <a href="https://www.tenable.com/security/tns-2021-05">https://www.tenable.com/security/tns-2021-05</a>
          <a href="https://www.tenable.com/security/tns-2021-06">https://www.tenable.com/security/tns-2021-06</a>
          <a href="https://www.tenable.com/security/tns-2021-09">https://www.tenable.com/security/tns-2021-09</a>
          <a href="https://www.tenable.com/security/tns-2021-10">https://www.tenable.com/security/tns-2021-10</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">musl</td>
        <td>CVE-2020-28928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.24-r0</td>
        <td>1.1.24-r3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2020/11/20/4">http://www.openwall.com/lists/oss-security/2020/11/20/4</a>
          <a href="https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/</a>
          <a href="https://musl.libc.org/releases.html">https://musl.libc.org/releases.html</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">musl-utils</td>
        <td>CVE-2020-28928</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.1.24-r0</td>
        <td>1.1.24-r3</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2020/11/20/4">http://www.openwall.com/lists/oss-security/2020/11/20/4</a>
          <a href="https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/r2134abfe847bea7795f0e53756d10a47e6643f35ab8169df8b8a9eb1@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/r90b60cf49348e515257b4950900c1bd3ab95a960cf2469d919c7264e@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2@%3Cnotifications.apisix.apache.org%3E">https://lists.apache.org/thread.html/ra63e8dc5137d952afc55dbbfa63be83304ecf842d1eab1ff3ebb29e2@%3Cnotifications.apisix.apache.org%3E</a>
          <a href="https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html">https://lists.debian.org/debian-lts-announce/2020/11/msg00050.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKQ3RVSMVZNZNO4D65W2CZZ4DMYFZN2Q/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UW27QVY7ERPTSGKS4KAWE5TU7EJWHKVQ/</a>
          <a href="https://musl.libc.org/releases.html">https://musl.libc.org/releases.html</a>
          <a href="https://www.oracle.com//security-alerts/cpujul2021.html">https://www.oracle.com//security-alerts/cpujul2021.html</a>
          <a href="https://www.oracle.com/security-alerts/cpuoct2021.html">https://www.oracle.com/security-alerts/cpuoct2021.html</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-28831</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r10</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-28831">https://access.redhat.com/security/cve/CVE-2021-28831</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831</a>
          <a href="https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd">https://git.busybox.net/busybox/commit/?id=f25d254dfd4243698c31a4f3153d4ac72aa9e9bd</a>
          <a href="https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html">https://lists.debian.org/debian-lts-announce/2021/04/msg00001.html</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3UDQGJRECXFS5EZVDH2OI45FMO436AC4/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Z7ZIFKPRR32ZYA3WAA2NXFA3QHHOU6FJ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZASBW7QRRLY5V2R44MQ4QQM4CZIDHM2U/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28831">https://nvd.nist.gov/vuln/detail/CVE-2021-28831</a>
          <a href="https://security.gentoo.org/glsa/202105-09">https://security.gentoo.org/glsa/202105-09</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42378</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42378">https://access.redhat.com/security/cve/CVE-2021-42378</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42378">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42378</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42378">https://nvd.nist.gov/vuln/detail/CVE-2021-42378</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42379</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42379">https://access.redhat.com/security/cve/CVE-2021-42379</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42379">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42379</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42379">https://nvd.nist.gov/vuln/detail/CVE-2021-42379</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42380</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42380">https://access.redhat.com/security/cve/CVE-2021-42380</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42380">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42380</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42380">https://nvd.nist.gov/vuln/detail/CVE-2021-42380</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42381</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42381">https://access.redhat.com/security/cve/CVE-2021-42381</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42381">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42381</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42381">https://nvd.nist.gov/vuln/detail/CVE-2021-42381</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42382</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42382">https://access.redhat.com/security/cve/CVE-2021-42382</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42382">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42382</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42382">https://nvd.nist.gov/vuln/detail/CVE-2021-42382</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42383</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42383">https://access.redhat.com/security/cve/CVE-2021-42383</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42384</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42384">https://access.redhat.com/security/cve/CVE-2021-42384</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42384">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42384</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42384">https://nvd.nist.gov/vuln/detail/CVE-2021-42384</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42385</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42385">https://access.redhat.com/security/cve/CVE-2021-42385</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42385">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42385</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42385">https://nvd.nist.gov/vuln/detail/CVE-2021-42385</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42386</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42386">https://access.redhat.com/security/cve/CVE-2021-42386</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42386">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42386</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42386">https://nvd.nist.gov/vuln/detail/CVE-2021-42386</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42374</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.31.1-r9</td>
        <td>1.31.1-r11</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-42374">https://access.redhat.com/security/cve/CVE-2021-42374</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42374">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42374</a>
          <a href="https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/">https://jfrog.com/blog/unboxing-busybox-14-new-vulnerabilities-uncovered-by-claroty-and-jfrog/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UQXGOGWBIYWOIVXJVRKHZR34UMEHQBXS/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42374">https://nvd.nist.gov/vuln/detail/CVE-2021-42374</a>
          <a href="https://security.netapp.com/advisory/ntap-20211223-0002/">https://security.netapp.com/advisory/ntap-20211223-0002/</a>
          <a href="https://ubuntu.com/security/notices/USN-5179-1">https://ubuntu.com/security/notices/USN-5179-1</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">node-pkg</th></tr>
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
