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
    <title>quay.io/argoproj/argocd:v2.2.3 (ubuntu 21.04) - Trivy Report - 2022-01-31 19:30:54.313894744 +0000 UTC m=+0.282686184 </title>
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
    <h1>quay.io/argoproj/argocd:v2.2.3 (ubuntu 21.04) - Trivy Report - 2022-01-31 19:30:54.313922245 +0000 UTC m=+0.282713585</h1>
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
      <tr class="severity-HIGH">
        <td class="pkg-name">linux-libc-dev</td>
        <td>CVE-2022-0185</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">5.11.0-46.51</td>
        <td>5.11.0-49.55</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-4155.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-4155.json</a>
          <a href="https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-0185.json">https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-0185.json</a>
          <a href="https://access.redhat.com/security/cve/CVE-2022-0185">https://access.redhat.com/security/cve/CVE-2022-0185</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0185">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0185</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de2">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de2</a>
          <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de29310e8aa03fcbdb41fc92c521756">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de29310e8aa03fcbdb41fc92c521756</a>
          <a href="https://github.com/Crusaders-of-Rust/CVE-2022-0185">https://github.com/Crusaders-of-Rust/CVE-2022-0185</a>
          <a href="https://linux.oracle.com/cve/CVE-2022-0185.html">https://linux.oracle.com/cve/CVE-2022-0185.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2022-9029.html">https://linux.oracle.com/errata/ELSA-2022-9029.html</a>
          <a href="https://ubuntu.com/security/notices/USN-5240-1">https://ubuntu.com/security/notices/USN-5240-1</a>
          <a href="https://www.openwall.com/lists/oss-security/2022/01/18/7">https://www.openwall.com/lists/oss-security/2022/01/18/7</a>
          <a href="https://www.willsroot.io/2022/01/cve-2022-0185.html">https://www.willsroot.io/2022/01/cve-2022-0185.html</a>
        </td>
      </tr>
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
      <tr class="severity-CRITICAL">
        <td class="pkg-name">PyYAML</td>
        <td>CVE-2020-14343</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">5.3.1</td>
        <td>5.4</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-14343">https://access.redhat.com/security/cve/CVE-2020-14343</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=1860466">https://bugzilla.redhat.com/show_bug.cgi?id=1860466</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14343">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14343</a>
          <a href="https://github.com/advisories/GHSA-8q59-q68h-6hv4">https://github.com/advisories/GHSA-8q59-q68h-6hv4</a>
          <a href="https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc">https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc</a>
          <a href="https://github.com/yaml/pyyaml/issues/420#issuecomment-663673966">https://github.com/yaml/pyyaml/issues/420#issuecomment-663673966</a>
          <a href="https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation">https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation</a>
          <a href="https://linux.oracle.com/cve/CVE-2020-14343.html">https://linux.oracle.com/cve/CVE-2020-14343.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2021-2583.html">https://linux.oracle.com/errata/ELSA-2021-2583.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-14343">https://nvd.nist.gov/vuln/detail/CVE-2020-14343</a>
          <a href="https://pypi.org/project/PyYAML/">https://pypi.org/project/PyYAML/</a>
          <a href="https://ubuntu.com/security/notices/USN-4940-1">https://ubuntu.com/security/notices/USN-4940-1</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">rsa</td>
        <td>CVE-2020-13757</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.4.2</td>
        <td>4.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-13757">https://access.redhat.com/security/cve/CVE-2020-13757</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13757">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13757</a>
          <a href="https://github.com/advisories/GHSA-537h-rv9q-vvph">https://github.com/advisories/GHSA-537h-rv9q-vvph</a>
          <a href="https://github.com/sybrenstuvel/python-rsa/issues/146">https://github.com/sybrenstuvel/python-rsa/issues/146</a>
          <a href="https://github.com/sybrenstuvel/python-rsa/issues/146#issuecomment-641845667">https://github.com/sybrenstuvel/python-rsa/issues/146#issuecomment-641845667</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KILTHBHNSDUCYV22ODLOKTICJJ7JQIQ/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2KILTHBHNSDUCYV22ODLOKTICJJ7JQIQ/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZYB65VNILRBTXL6EITQTH2PZPK7I23MW/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZYB65VNILRBTXL6EITQTH2PZPK7I23MW/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-13757">https://nvd.nist.gov/vuln/detail/CVE-2020-13757</a>
          <a href="https://ubuntu.com/security/notices/USN-4478-1">https://ubuntu.com/security/notices/USN-4478-1</a>
          <a href="https://usn.ubuntu.com/4478-1/">https://usn.ubuntu.com/4478-1/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">rsa</td>
        <td>CVE-2020-25658</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">3.4.2</td>
        <td>4.7</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-25658">https://access.redhat.com/security/cve/CVE-2020-25658</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-25658">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-25658</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25658">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25658</a>
          <a href="https://github.com/advisories/GHSA-xrx6-fmxq-rjj2">https://github.com/advisories/GHSA-xrx6-fmxq-rjj2</a>
          <a href="https://github.com/sybrenstuvel/python-rsa/commit/dae8ce0d85478e16f2368b2341632775313d41ed">https://github.com/sybrenstuvel/python-rsa/commit/dae8ce0d85478e16f2368b2341632775313d41ed</a>
          <a href="https://github.com/sybrenstuvel/python-rsa/issues/165">https://github.com/sybrenstuvel/python-rsa/issues/165</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2SAF67KDGSOHLVFTRDOHNEAFDRSSYIWA/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2SAF67KDGSOHLVFTRDOHNEAFDRSSYIWA/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APF364QJ2IYLPDNVFBOEJ24QP2WLVLJP/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/APF364QJ2IYLPDNVFBOEJ24QP2WLVLJP/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QY4PJWTYSOV7ZEYZVMYIF6XRU73CY6O7/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QY4PJWTYSOV7ZEYZVMYIF6XRU73CY6O7/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-25658">https://nvd.nist.gov/vuln/detail/CVE-2020-25658</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">urllib3</td>
        <td>CVE-2021-33503</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.25.11</td>
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
      <tr class="group-header"><th colspan="6">gobinary</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">go.mongodb.org/mongo-driver</td>
        <td>CVE-2021-20329</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.1.1</td>
        <td>1.5.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20329">https://access.redhat.com/security/cve/CVE-2021-20329</a>
          <a href="https://github.com/advisories/GHSA-f6mq-5m25-4r72">https://github.com/advisories/GHSA-f6mq-5m25-4r72</a>
          <a href="https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca">https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca</a>
          <a href="https://github.com/mongodb/mongo-go-driver/pull/622">https://github.com/mongodb/mongo-go-driver/pull/622</a>
          <a href="https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1">https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1</a>
          <a href="https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml">https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml</a>
          <a href="https://jira.mongodb.org/browse/GODRIVER-1923">https://jira.mongodb.org/browse/GODRIVER-1923</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-20329">https://nvd.nist.gov/vuln/detail/CVE-2021-20329</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2020-8554</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.22.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8554">https://access.redhat.com/security/cve/CVE-2020-8554</a>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">go.mongodb.org/mongo-driver</td>
        <td>CVE-2021-20329</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.1.1</td>
        <td>1.5.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20329">https://access.redhat.com/security/cve/CVE-2021-20329</a>
          <a href="https://github.com/advisories/GHSA-f6mq-5m25-4r72">https://github.com/advisories/GHSA-f6mq-5m25-4r72</a>
          <a href="https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca">https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca</a>
          <a href="https://github.com/mongodb/mongo-go-driver/pull/622">https://github.com/mongodb/mongo-go-driver/pull/622</a>
          <a href="https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1">https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1</a>
          <a href="https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml">https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml</a>
          <a href="https://jira.mongodb.org/browse/GODRIVER-1923">https://jira.mongodb.org/browse/GODRIVER-1923</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-20329">https://nvd.nist.gov/vuln/detail/CVE-2021-20329</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2020-8554</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.22.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8554">https://access.redhat.com/security/cve/CVE-2020-8554</a>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">go.mongodb.org/mongo-driver</td>
        <td>CVE-2021-20329</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.1.1</td>
        <td>1.5.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-20329">https://access.redhat.com/security/cve/CVE-2021-20329</a>
          <a href="https://github.com/advisories/GHSA-f6mq-5m25-4r72">https://github.com/advisories/GHSA-f6mq-5m25-4r72</a>
          <a href="https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca">https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca</a>
          <a href="https://github.com/mongodb/mongo-go-driver/pull/622">https://github.com/mongodb/mongo-go-driver/pull/622</a>
          <a href="https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1">https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1</a>
          <a href="https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml">https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0112.yaml</a>
          <a href="https://jira.mongodb.org/browse/GODRIVER-1923">https://jira.mongodb.org/browse/GODRIVER-1923</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-20329">https://nvd.nist.gov/vuln/detail/CVE-2021-20329</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">k8s.io/kubernetes</td>
        <td>CVE-2020-8554</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.22.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2020-8554">https://access.redhat.com/security/cve/CVE-2020-8554</a>
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
        <td class="pkg-name">github.com/docker/cli</td>
        <td>CVE-2021-41092</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">v20.10.7+incompatible</td>
        <td>v20.10.9</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2021-41092">https://access.redhat.com/security/cve/CVE-2021-41092</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41092">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41092</a>
          <a href="https://github.com/docker/cli/commit/893e52cf4ba4b048d72e99748e0f86b2767c6c6b">https://github.com/docker/cli/commit/893e52cf4ba4b048d72e99748e0f86b2767c6c6b</a>
          <a href="https://github.com/docker/cli/security/advisories/GHSA-99pg-grm5-qq3v">https://github.com/docker/cli/security/advisories/GHSA-99pg-grm5-qq3v</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B5Q6G6I4W5COQE25QMC7FJY3I3PAYFBB/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B5Q6G6I4W5COQE25QMC7FJY3I3PAYFBB/</a>
          <a href="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZNFADTCHHYWVM6W4NJ6CB4FNFM2VMBIB/">https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZNFADTCHHYWVM6W4NJ6CB4FNFM2VMBIB/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-41092">https://nvd.nist.gov/vuln/detail/CVE-2021-41092</a>
          <a href="https://ubuntu.com/security/notices/USN-5134-1">https://ubuntu.com/security/notices/USN-5134-1</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">gobinary</th></tr>
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
