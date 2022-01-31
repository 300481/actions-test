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
    <title>bin/operator - Trivy Report - 2022-01-31T14:31:47.923214045Z</title>
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
    <h1>bin/operator - Trivy Report - 2022-01-31T14:31:47.923230045Z</h1>
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
      <tr class="severity-MEDIUM">
        <td class="pkg-name">github.com/prometheus/prometheus</td>
        <td>CVE-2019-3826</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">v1.8.2-0.20211214150951-52c693a63be1</td>
        <td>v2.7.1</td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHBA-2019:0327">https://access.redhat.com/errata/RHBA-2019:0327</a>
          <a href="https://advisory.checkmarx.net/advisory/CX-2019-4297">https://advisory.checkmarx.net/advisory/CX-2019-4297</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3826">https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3826</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3826">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3826</a>
          <a href="https://github.com/prometheus/prometheus/commit/62e591f9">https://github.com/prometheus/prometheus/commit/62e591f9</a>
          <a href="https://github.com/prometheus/prometheus/pull/5163">https://github.com/prometheus/prometheus/pull/5163</a>
          <a href="https://lists.apache.org/thread.html/r48d5019bd42e0770f7e5351e420a63a41ff1f16924942442c6aff6a8@%3Ccommits.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r48d5019bd42e0770f7e5351e420a63a41ff1f16924942442c6aff6a8@%3Ccommits.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r8e3f7da12bf5750b0a02e69a78a61073a2ac950eed7451ce70a65177@%3Ccommits.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/r8e3f7da12bf5750b0a02e69a78a61073a2ac950eed7451ce70a65177@%3Ccommits.zookeeper.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rdf2a0d94c3b5b523aeff7741ae71347415276062811b687f30ea6573@%3Ccommits.zookeeper.apache.org%3E">https://lists.apache.org/thread.html/rdf2a0d94c3b5b523aeff7741ae71347415276062811b687f30ea6573@%3Ccommits.zookeeper.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3826">https://nvd.nist.gov/vuln/detail/CVE-2019-3826</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
