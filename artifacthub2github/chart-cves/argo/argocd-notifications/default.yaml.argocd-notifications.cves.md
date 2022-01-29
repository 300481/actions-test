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
    <title>app/argocd-notifications - Trivy Report - 2022-01-29T16:24:11.163035272Z</title>
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
    <h1>app/argocd-notifications - Trivy Report - 2022-01-29T16:24:11.163051073Z</h1>
    <table>
      <tr class="group-header"><th colspan="6">gobinary</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">github.com/dgrijalva/jwt-go</td>
        <td>CVE-2020-26160</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">v3.2.0+incompatible</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/dgrijalva/jwt-go/pull/426">https://github.com/dgrijalva/jwt-go/pull/426</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-26160">https://nvd.nist.gov/vuln/detail/CVE-2020-26160</a>
          <a href="https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515">https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2020-8554</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.21.0</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://blog.champtar.fr/K8S_MITM_LoadBalancer_ExternalIPs/">https://blog.champtar.fr/K8S_MITM_LoadBalancer_ExternalIPs/</a>
          <a href="https://github.com/kubernetes/kubernetes/issues/97076">https://github.com/kubernetes/kubernetes/issues/97076</a>
          <a href="https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8">https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8554.html">https://linux.oracle.com/cve/CVE-2020-8554.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9029.html">https://linux.oracle.com/errata/ELSA-2021-9029.html</a>
          <a href="https://lists.apache.org/thread.html/r0c76b3d0be348f788cd947054141de0229af00c540564711e828fd40@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r0c76b3d0be348f788cd947054141de0229af00c540564711e828fd40@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r1975078e44d96f2a199aa90aa874b57a202eaf7f25f2fde6d1c44942@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r1975078e44d96f2a199aa90aa874b57a202eaf7f25f2fde6d1c44942@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rcafa485d63550657f068775801aeb706b7a07140a8ebbdef822b3bb3@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rcafa485d63550657f068775801aeb706b7a07140a8ebbdef822b3bb3@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rdb223e1b82e3d7d8e4eaddce8dd1ab87252e3935cc41c859f49767b6@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rdb223e1b82e3d7d8e4eaddce8dd1ab87252e3935cc41c859f49767b6@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8554">https://nvd.nist.gov/vuln/detail/CVE-2020-8554</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2021-25737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.21.0</td>
        <td>1.18.19, 1.19.10, 1.20.7, 1.21.1</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/kubernetes/kubernetes/issues/102106">https://github.com/kubernetes/kubernetes/issues/102106</a>
          <a href="https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY">https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-25737">https://nvd.nist.gov/vuln/detail/CVE-2021-25737</a>
          <a href="https://security.netapp.com/advisory/ntap-20211004-0004/">https://security.netapp.com/advisory/ntap-20211004-0004/</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">gobinary</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">github.com/dgrijalva/jwt-go</td>
        <td>CVE-2020-26160</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">v3.2.0+incompatible</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/dgrijalva/jwt-go/pull/426">https://github.com/dgrijalva/jwt-go/pull/426</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-26160">https://nvd.nist.gov/vuln/detail/CVE-2020-26160</a>
          <a href="https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515">https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2020-8554</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.21.0</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://blog.champtar.fr/K8S_MITM_LoadBalancer_ExternalIPs/">https://blog.champtar.fr/K8S_MITM_LoadBalancer_ExternalIPs/</a>
          <a href="https://github.com/kubernetes/kubernetes/issues/97076">https://github.com/kubernetes/kubernetes/issues/97076</a>
          <a href="https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8">https://groups.google.com/g/kubernetes-security-announce/c/iZWsF9nbKE8</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-8554.html">https://linux.oracle.com/cve/CVE-2020-8554.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-9029.html">https://linux.oracle.com/errata/ELSA-2021-9029.html</a>
          <a href="https://lists.apache.org/thread.html/r0c76b3d0be348f788cd947054141de0229af00c540564711e828fd40@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r0c76b3d0be348f788cd947054141de0229af00c540564711e828fd40@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r1975078e44d96f2a199aa90aa874b57a202eaf7f25f2fde6d1c44942@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r1975078e44d96f2a199aa90aa874b57a202eaf7f25f2fde6d1c44942@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rcafa485d63550657f068775801aeb706b7a07140a8ebbdef822b3bb3@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rcafa485d63550657f068775801aeb706b7a07140a8ebbdef822b3bb3@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rdb223e1b82e3d7d8e4eaddce8dd1ab87252e3935cc41c859f49767b6@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rdb223e1b82e3d7d8e4eaddce8dd1ab87252e3935cc41c859f49767b6@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8554">https://nvd.nist.gov/vuln/detail/CVE-2020-8554</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2021-25737</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.21.0</td>
        <td>1.18.19, 1.19.10, 1.20.7, 1.21.1</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/kubernetes/kubernetes/issues/102106">https://github.com/kubernetes/kubernetes/issues/102106</a>
          <a href="https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY">https://groups.google.com/g/kubernetes-security-announce/c/xAiN3924thY</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-25737">https://nvd.nist.gov/vuln/detail/CVE-2021-25737</a>
          <a href="https://security.netapp.com/advisory/ntap-20211004-0004/">https://security.netapp.com/advisory/ntap-20211004-0004/</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
