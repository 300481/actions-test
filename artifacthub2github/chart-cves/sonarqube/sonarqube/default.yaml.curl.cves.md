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
    <title>curlimages/curl:7.76.1 (alpine 3.12.6) - Trivy Report - 2022-01-31 16:01:43.928895226 +0000 UTC m=+0.493532082 </title>
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
    <h1>curlimages/curl:7.76.1 (alpine 3.12.6) - Trivy Report - 2022-01-31 16:01:43.928922027 +0000 UTC m=+0.493558983</h1>
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
        <td class="pkg-version">2.10.5-r1</td>
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
        <td class="pkg-version">2.10.5-r1</td>
        <td>2.10.6-r0</td>
        <td class="links" data-more-links="off">
          <a href="https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10741">https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10741</a>
          <a href="https://gitlab.alpinelinux.org/alpine/aports/-/issues/12606">https://gitlab.alpinelinux.org/alpine/aports/-/issues/12606</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">busybox</td>
        <td>CVE-2021-42378</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.1.1k-r0</td>
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
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1k-r0</td>
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
      <tr class="severity-CRITICAL">
        <td class="pkg-name">libssl1.1</td>
        <td>CVE-2021-3711</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.1.1k-r0</td>
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
        <td>CVE-2021-3712</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.1.1k-r0</td>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">ssl_client</td>
        <td>CVE-2021-42378</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
        <td class="pkg-version">1.31.1-r20</td>
        <td>1.31.1-r21</td>
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
    </table>
  </body>
</html>
