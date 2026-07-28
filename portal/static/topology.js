/* topology.js — D3 force-directed network graph consuming /api/topology. */
(function () {
  "use strict";

  const W = window.Watchtower = window.Watchtower || {};

  const topology = {
    mount: function () {
      const canvas = document.getElementById("topology-canvas");
      if (!canvas) return;
      if (typeof d3 === "undefined") {
        canvas.textContent = "d3 library failed to load";
        return;
      }

      const legend = document.getElementById("topology-legend");
      const refreshBtn = document.getElementById("topology-refresh");
      if (refreshBtn) refreshBtn.addEventListener("click", load);

      const svg = d3.select(canvas).append("svg")
        .attr("viewBox", "0 0 800 500")
        .attr("preserveAspectRatio", "xMidYMid meet");
      const linkGroup = svg.append("g").attr("class", "links");
      const nodeGroup = svg.append("g").attr("class", "nodes");

      let simulation = null;

      function load() {
        W.api.topology().then(render).catch(function (err) { W.showError(err); });
      }

      function colorFor(kind) {
        const map = { router: "#7cf3c7", switch: "#6bb8ff", firewall: "#f2c34e", server: "#ff6a6a", endpoint: "#b6c2d1" };
        return map[String(kind || "").toLowerCase()] || "#8b9aae";
      }

      function render(graph) {
        const nodes = Array.isArray(graph.nodes) ? graph.nodes.slice() : [];
        const links = Array.isArray(graph.edges) ? graph.edges.slice() : [];
        if (legend) legend.textContent = nodes.length + " nodes / " + links.length + " links";

        if (simulation) simulation.stop();
        simulation = d3.forceSimulation(nodes)
          .force("link", d3.forceLink(links).id(function (d) { return d.id; }).distance(90).strength(0.6))
          .force("charge", d3.forceManyBody().strength(-220))
          .force("center", d3.forceCenter(400, 250))
          .force("collide", d3.forceCollide(28));

        const link = linkGroup.selectAll("line").data(links, function (d) { return d.source + "-" + d.target; });
        link.exit().remove();
        const linkEnter = link.enter().append("line").attr("class", "link");
        const allLinks = linkEnter.merge(link);

        const node = nodeGroup.selectAll("g.node").data(nodes, function (d) { return d.id; });
        node.exit().remove();
        const nodeEnter = node.enter().append("g").attr("class", "node");
        nodeEnter.append("circle").attr("r", 14).attr("fill", function (d) { return colorFor(d.kind || d.classification); });
        nodeEnter.append("text").attr("dy", 28).attr("text-anchor", "middle").text(function (d) { return d.label || d.hostname || d.ip || d.id; });
        const allNodes = nodeEnter.merge(node);
        nodeEnter.call(d3.drag()
          .on("start", function (event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
          .on("drag", function (event, d) { d.fx = event.x; d.fy = event.y; })
          .on("end", function (event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
        );

        simulation.on("tick", function () {
          allLinks
            .attr("x1", function (d) { return d.source.x; })
            .attr("y1", function (d) { return d.source.y; })
            .attr("x2", function (d) { return d.target.x; })
            .attr("y2", function (d) { return d.target.y; });
          allNodes.attr("transform", function (d) { return "translate(" + d.x + "," + d.y + ")"; });
        });
      }

      load();
    }
  };

  W.topology = topology;
})();
