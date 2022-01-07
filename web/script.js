/* globals document, window, console, URLSearchParams, XMLHttpRequest, $, history */

(function () {
  "use strict";
  // const LOGS_BASE_URL = "https://f000.backblazeb2.com/file/quic-interop-runner-sat/";
  // const LOGS_BASE_URL = "https://interop.sedrubal.de/";
  const LOGS_BASE_URL = window.location.href.split("?")[0];
  // const INDEX = "index.html";
  const INDEX = "";
  const QVIS_BASE_URL = "https://qvis.quictools.info/";
  const map = { client: {}, server: {}, test: {} };
  const color_type = {
    succeeded: "success",
    unsupported: "secondary disabled",
    failed: "danger",
  };

  // see https://stackoverflow.com/a/43466724/
  function formatTime(seconds) {
    return [
      parseInt(seconds / 60 / 60),
      parseInt((seconds / 60) % 60),
      parseInt(seconds % 60),
    ]
      .join(":")
      .replace(/\b(\d)\b/g, "0$1");
  }

  function getLogLink(type, log_dir, server, client, test_result, test_desc) {
    var ttip = `
      <b>Test:</b> ${test_desc.name}<br/>
      <b>Client:</b> ${client}<br/>
      <b>Server:</b> ${server}<br/>
      <b>Result: <span class="badge badge-${color_type[test_result.result]}">${
      test_result.result
    }</span></b>
    `;

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = `btn btn-xs btn-${color_type[test_result.result]} ${
      test_result.result
    } test-${test_result.abbr.toLowerCase()}`;
    if (type === "measurement" && test_result.result === "succeeded") {
      try {
        const rating =
          Number.parseInt(test_result.details.split(" ")[0]) /
          test_desc.theoretical_max_value;
        const adaptedRating = Math.min(1, rating * 2);

        ttip += `<br/><b>Efficiency:</b> <span class="badge badge-dark calc-rating rating-color" style="--rating: ${adaptedRating};">${(
          rating * 100
        ).toFixed(0)} %</span>`;

        btn.style.setProperty("--rating", adaptedRating);
        btn.className += " calc-rating btn-rating";
      } catch (e) {
        console.error(
          "Measurement details did not parse:",
          test_result.details
        );
      }
    }
    var ttip_target = btn;
    if (test_result.result !== "unsupported") {
      const log_url = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/${INDEX}`;
      btn.href = log_url;
      btn.target = "_blank";
      // popover
      ttip += `<p><div class="btn-group-vertical w-100">
        <a class="btn btn-sm btn-secondary" href="${log_url}" target="_blank">Open Logs</a>`;
      // if (test_result.result == "succeeded") {
      //   if (type == "testcase") {
      //     const qlog_server_url = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/server.qlog`;
      //     const qlog_client_url = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/client.qlog`;
      //     const qvis_url = `${QVIS_BASE_URL}#/files?list=${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/server.qlog`;
      //     ttip += `<a class="btn btn-sm btn-outline-secondary" href="${qvis_url}" target="_blank">Open qlog in qvis*</a>`;
      //   } else {
      //     for (let i = 1, len = test_desc.repetitions || 1; i <= len; i++) {
      //       const qlog_server_url = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/${i}/server.qlog`;
      //       const qlog_client_url = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${test_desc.name}/${i}/client.qlog`;
      //       const qvis_url = `${QVIS_BASE_URL}#?file1=${qlog_server_url}&file2=${qlog_client_url}`;
      //       ttip += `<a class="btn btn-sm btn-outline-secondary" href="${qvis_url}" target="_blank">Open qlog #${i} in qvis*</a>`;
      //     }
      //   }
      // }
      ttip += `</div></p>`;
      // if (test_result.result == "succeeded") {
      //   ttip += '<small><i class="text-muted">*qlog files may not exist</i></small>';
      // }
    }
    $(ttip_target)
      .attr("data-toggle", "popover")
      .attr("data-placement", "bottom")
      .attr("data-trigger", "click")
      .attr("data-content", ttip)
      .attr("data-html", true)
      .popover({ sanitize: false })
      .on("show.bs.popover", function (evt) {
        // close all other popovers
        $("[data-toggle=popover]").not(this).popover("hide");
      });
    btn.appendChild(document.createTextNode(test_result.abbr));
    return ttip_target;
  }

  function makeClickable(e, url) {
    e.title = url;
    $(e)
      .attr("role", "button")
      .attr("data-href", url)
      .attr("data-toggle", "tooltip")
      .tooltip();
    e.onclick = function (e) {
      window.open(e.target.getAttribute("data-href"));
    };
  }

  function makeColumnHeaders(t, result) {
    for (var i = 0; i <= result.servers.length + 1; i++) {
      t.appendChild(document.createElement("colgroup"));
    }
    var thead = t.createTHead();
    var row = thead.insertRow(0);
    var cell = document.createElement("th");
    row.appendChild(cell);
    cell.scope = "col";
    cell.className = "table-light client-any";
    for (var i = 0; i < result.servers.length; i++) {
      cell = document.createElement("th");
      row.appendChild(cell);
      cell.scope = "col";
      const serverName = result.servers[i];
      const compliant = result.images
        ? result.images[serverName].compliant
        : undefined;
      cell.className = compliant === false ? "table-warning" : "table-light";
      cell.classList.add(`server-${serverName}`);
      if (result.hasOwnProperty("urls")) {
        makeClickable(cell, result.urls[serverName]);
      }
      cell.innerHTML = serverName;
    }
  }

  function makeRowHeader(tbody, result, i) {
    var row = tbody.insertRow(i);
    var cell = document.createElement("th");
    cell.scope = "row";
    const clientName = result.clients[i];
    const compliant = result.images
      ? result.images[clientName].compliant
      : undefined;
    cell.className = compliant === false ? "table-warning" : "table-light";
    cell.classList.add(`client-${clientName}`);
    if (result.hasOwnProperty("urls")) {
      makeClickable(cell, result.urls[result.clients[i]]);
    }
    cell.innerHTML = result.clients[i];
    row.appendChild(cell);
    return row;
  }

  function fillInteropTable(result, log_dir) {
    var index = 0;
    var appendResult = function (el, res, i, j) {
      result.results[index].forEach(function (test_result) {
        if (test_result.result !== res) return;
        el.appendChild(
          getLogLink(
            "testcase",
            log_dir,
            result.servers[j],
            result.clients[i],
            test_result,
            result.tests[test_result.abbr]
          )
        );
      });
    };

    var t = document.getElementById("interop");
    t.innerHTML = "";
    makeColumnHeaders(t, result);
    var tbody = t.createTBody();
    for (var i = 0; i < result.clients.length; i++) {
      var row = makeRowHeader(tbody, result, i);
      for (var j = 0; j < result.servers.length; j++) {
        var cell = row.insertCell(j + 1);
        cell.className = `server-${result.servers[j]} client-${result.clients[i]}`;
        appendResult(cell, "succeeded", i, j);
        appendResult(cell, "unsupported", i, j);
        appendResult(cell, "failed", i, j);
        index++;
      }
    }
  }

  function fillMeasurementTable(result, log_dir) {
    var t = document.getElementById("measurements");
    t.innerHTML = "";
    makeColumnHeaders(t, result);
    var tbody = t.createTBody();
    var index = 0;
    for (var i = 0; i < result.clients.length; i++) {
      var row = makeRowHeader(tbody, result, i);
      row.className = `row-${result.clients[i]}`;
      for (var j = 0; j < result.servers.length; j++) {
        var res = result.measurements[index];
        var cell = row.insertCell(j + 1);
        cell.className = `server-${result.servers[j]} client-${result.clients[i]}`;
        const btnGroup = document.createElement("div");
        btnGroup.className = "btn-group-vertical";
        cell.appendChild(btnGroup);
        res
          .sort((a, b) =>
            a["abbr"] < b["abbr"] ? -1 : a["abbr"] > b["abbr"] ? 1 : 0
          )
          .forEach((meas_result) => {
            const measurement = result.tests[meas_result.abbr];
            if (!meas_result.result) {
              return;
            }
            var link = getLogLink(
              "measurement",
              log_dir,
              result.servers[j],
              result.clients[i],
              meas_result,
              measurement
            );
            if (meas_result.result === "succeeded") {
              link.innerHTML += ": " + meas_result.details;
            }
            btnGroup.appendChild(link);
          });
        index++;
      }
    }
    // add efficiency row and col
    // collect efficiencies
    var effsByCombi = result.servers.map(() => result.clients.map(() => null));
    for (var c = 0; c < result.clients.length; c++) {
      for (var s = 0; s < result.servers.length; s++) {
        var measResults = result.measurements[c * result.servers.length + s];
        var effsForCombi = {};
        measResults.forEach((measResult) => {
          if (measResult.result == "succeeded") {
            const eff =
              Number.parseInt(measResult.details.split(" ")[0]) /
              result.tests[measResult.abbr].theoretical_max_value;
            effsForCombi[measResult.abbr] = eff;
          } else {
            effsForCombi[measResult.abbr] = null;
          }
        });
        effsByCombi[s][c] = effsForCombi;
      }
    }

    // create html elements

    // calculate avg effs for servers
    const effRow = document.createElement("tr");
    effRow.className = "eff-row";
    tbody.appendChild(effRow);
    var cell = document.createElement("th");
    cell.scope = "row";
    cell.className = "table-light eff-title";
    cell.innerHTML = "Efficiency";
    effRow.appendChild(cell);

    for (var s = 0; s < result.servers.length; s++) {
      var serverEffsByMeas = {};
      for (var c = 0; c < result.clients.length; c++) {
        const effForCombi = effsByCombi[s][c];
        Object.entries(effForCombi).forEach(([abbr, eff]) => {
          const serverEffsForMeas = serverEffsByMeas[abbr] || [];
          serverEffsForMeas.push(eff);
          serverEffsByMeas[abbr] = serverEffsForMeas;
        });
      }
      var cell = createEffCell(serverEffsByMeas, `server-${result.servers[s]}`);
      effRow.appendChild(cell);
    }
    // add right lower cell
    cell = document.createElement("th");
    cell.className = "table-light eff-title";
    effRow.appendChild(cell);

    // calculate avg effs for clients
    cell = document.createElement("th");
    cell.scope = "col";
    cell.className = "table-light eff-title";
    cell.innerHTML = "Efficiency";
    t.tHead.querySelector("tr").appendChild(cell);

    for (var c = 0; c < result.clients.length; c++) {
      var clientEffsByMeas = {};
      for (var s = 0; s < result.servers.length; s++) {
        const effForCombi = effsByCombi[s][c];
        Object.entries(effForCombi).forEach(([abbr, eff]) => {
          const clientEffsForMeas = clientEffsByMeas[abbr] || [];
          clientEffsForMeas.push(eff);
          clientEffsByMeas[abbr] = clientEffsForMeas;
        });
      }
      var cell = createEffCell(clientEffsByMeas, `client-${result.clients[c]}`);
      tbody.querySelector(`.row-${result.clients[c]}`).appendChild(cell);
    }
  }

  function fillPlotsTable() {
    const result = window.result;
    const log_dir = window.log_dir;
    const measAbbr = window.showPlotsForMeasurement;
    const measurement = result.tests[measAbbr].name;
    // fill table
    var t = document.getElementById("plots");
    t.innerHTML = "";
    makeColumnHeaders(t, result);
    var tbody = t.createTBody();
    var index = 0;
    for (var c = 0; c < result.clients.length; c++) {
      var row = makeRowHeader(tbody, result, c);
      row.className = `row-${result.clients[c]}`;
      for (var s = 0; s < result.servers.length; s++) {
        var cell = row.insertCell(s + 1);
        cell.className = `server-${result.servers[s]} client-${result.clients[c]}`;
        const testResult = result.measurements[
          c * result.servers.length + s
        ].filter((r) => r.abbr === measAbbr)[0];
        const wrapper = document.createElement("div");
        if (!testResult) {
          wrapper.innerHTML = `<span class="badge badge-warning">No Result Found</span>`;
        } else if (testResult.result === "succeeded") {
          const server = result.servers[s];
          const client = result.clients[c];
          const imgSrc = `${LOGS_BASE_URL}logs/${log_dir}/${server}_${client}/${measurement}/time_offset-number_plot.png`;
          wrapper.innerHTML = `
            <a href="${imgSrc}" target="_blank">
              <img class="plot" src="${imgSrc}" alt="🚫" title="server=${server} client=${client} measurement=${measurement}" />
            </a>
          `;
        } else {
          wrapper.innerHTML = `<span class="badge badge-danger">Test Failed</span>`;
        }
        cell.appendChild(wrapper);
        index++;
      }
    }
  }

  function createEffCell(effsByMeas, className) {
    var cell = document.createElement("th");
    cell.className = `table-light eff-cell ${className}`;
    const btnGroup = document.createElement("div");
    btnGroup.className = "btn-group-vertical";
    cell.appendChild(btnGroup);
    Object.entries(effsByMeas).forEach(([abbr, effs]) => {
      const avgEff =
        effs.reduce((acc, cur) => acc + cur, 0) /
        effs.filter((e) => e !== null).length;
      const badge = document.createElement("span");
      var avgEffStr = "";
      if (isNaN(avgEff)) {
        avgEffStr = "-";
        badge.className = `btn btn-xs btn-secondary disabled test-${abbr.toLowerCase()}`;
      } else {
        avgEffStr = `${(avgEff * 100).toFixed(0)} %`;
        badge.className = `btn btn-xs calc-rating btn-rating test-${abbr.toLowerCase()}`;
        const adaptedRating = Math.min(1, avgEff * 2);
        badge.style.setProperty("--rating", adaptedRating);
      }
      badge.innerHTML = `${abbr}: ${avgEffStr}`;
      btnGroup.appendChild(badge);
    });
    return cell;
  }

  function dateToString(date) {
    return (
      date.toLocaleDateString("en-US", { timeZone: "UTC" }) +
      " " +
      date.toLocaleTimeString("en-US", {
        timeZone: "UTC",
        timeZoneName: "short",
      })
    );
  }

  function makeButton(type, text, tooltip, compliant) {
    var b = document.createElement("button");
    b.innerHTML = text;
    b.id = type + "-" + text.toLowerCase();
    if (tooltip) {
      b.title = tooltip;
      $(b)
        .attr("data-toggle", "tooltip")
        .attr("data-placement", "bottom")
        .attr("data-html", true)
        .tooltip();
    }
    b.type = "button";
    b.className = `${type} btn`;
    if (compliant === undefined || compliant === null || compliant) {
      b.classList.add("btn-light");
    } else {
      b.classList.add("btn-warning");
      b.title = "not compliant";
      $(b)
        .attr("data-toggle", "tooltip")
        .attr("data-placement", "bottom")
        .attr("data-html", true)
        .tooltip();
    }
    $(b).click(clickButton);
    return b;
  }

  function toggleHighlight(e) {
    const comp = e.target.id.split("-");
    const which = "." + comp[0] + "-" + comp[1] + "." + comp[2];
    $(which).toggleClass("btn-highlight");
  }

  function setButtonState() {
    var params = new URLSearchParams(
      history.state ? history.state.path : window.location.search
    );
    var show = {};
    Object.keys(map).forEach((type) => {
      map[type] = params
        .getAll(type)
        .map((x) => x.toLowerCase().split(","))
        .flat();
      if (map[type].length === 0)
        map[type] = $("#" + type + " :button")
          .get()
          .map((x) => x.id.replace(type + "-", ""));
      $("#" + type + " :button")
        .removeClass("active font-weight-bold")
        .addClass("text-muted font-weight-light")
        .filter((i, e) => map[type].includes(e.id.replace(type + "-", "")))
        .addClass("active font-weight-bold")
        .removeClass("text-muted font-weight-light");
      show[type] = map[type].map((e) => "." + type + "-" + e);
    });

    $(".result td")
      .add(".result th")
      .add(".result td .btn")
      .add(".result th .badge")
      .not(".eff-title")
      .hide();

    const show_classes = show.client
      .map((el1) => show.server.map((el2) => el1 + el2))
      .flat()
      .join();
    $(".client-any," + show_classes).show();
    $(show.server.map((serverCls) => `.eff-cell${serverCls}`).join(",")).show();
    $(show.client.map((clientCls) => `.eff-cell${clientCls}`).join(",")).show();

    $(".result " + show.client.map((e) => "th" + e).join()).show();
    $(".result " + show.server.map((e) => "th" + e).join()).show();
    $(".measurement," + show.test.join()).show();

    $("#test :button").each((i, e) => {
      $(e).find("span,br").remove();
      var count = { succeeded: 0, unsupported: 0, failed: 0 };
      Object.keys(count).map(
        (c) => (count[c] = $(".btn." + e.id + "." + c + ":visible").length)
      );
      Object.keys(count).map((c) => {
        e.appendChild(document.createElement("br"));
        var b = document.createElement("span");
        b.innerHTML = count[c];
        b.className = "btn btn-xs btn-" + color_type[c];
        if (e.classList.contains("active") === false)
          b.className += " disabled";
        b.id = e.id + "-" + c;
        $(b).hover(toggleHighlight, toggleHighlight);
        e.appendChild(b);
      });
    });
  }

  function clickButton(e) {
    function toggle(array, value) {
      var index = array.indexOf(value);
      if (index === -1) {
        array.push(value);
      } else {
        array.splice(index, 1);
      }
    }

    var b = $(e.target).closest(":button")[0];
    b.blur();
    const type = [...b.classList].filter((x) =>
      Object.keys(map).includes(x)
    )[0];
    const which = b.id.replace(type + "-", "");

    var params = new URLSearchParams(
      history.state ? history.state.path : window.location.search
    );
    if (params.has(type) && params.get(type))
      map[type] = params.get(type).split(",");
    else
      map[type] = $("#" + type + " :button")
        .get()
        .map((e) => e.id.replace(type + "-", ""));

    toggle(map[type], which);
    params.set(type, map[type]);
    if (map[type].length === $("#" + type + " :button").length)
      params.delete(type);

    const comp = decodeURIComponent(params.toString());
    var refresh =
      window.location.protocol +
      "//" +
      window.location.host +
      window.location.pathname +
      (comp ? "?" + comp : "");
    window.history.pushState(null, null, refresh);

    setButtonState();
    return false;
  }

  function makeTooltip(name, desc, timeout) {
    return (
      "<strong>" +
      name +
      "</strong>" +
      (desc === undefined ? "" : "<br>" + desc) +
      (timeout ? `<br><b>Test Timeout:</b> ${timeout} s` : "")
    );
  }

  function process(result, log_dir) {
    window.result = result;
    window.log_dir = log_dir;
    var startTime = new Date(1000 * result.start_time);
    var endTime = new Date(1000 * result.end_time);
    var duration = result.end_time - result.start_time;
    document.getElementById("lastrun-start").innerHTML =
      dateToString(startTime);
    document.getElementById("lastrun-end").innerHTML = dateToString(endTime);
    document.getElementById("duration").innerHTML = formatTime(duration);
    document.getElementById("quic-vers").innerHTML =
      "<tt>" +
      result.quic_version +
      '</tt> ("draft-' +
      result.quic_draft +
      '")';

    // update plot measurement select
    window.showPlotsForMeasurement = Object.keys(result.tests).pop();
    const select = document.getElementById("plot-measurement-select");
    select.textContent = "";
    Object.entries(result.tests).forEach(([measAbbr, meas]) => {
      const option = document.createElement("option");
      option.value = measAbbr;
      option.innerText = `${meas.name} (${measAbbr})`;
      if (window.showPlotsForMeasurement == measAbbr) {
        option.selected = "selected";
      }
      select.appendChild(option);
    });
    select.addEventListener("change", (evt) => {
      window.showPlotsForMeasurement = evt.currentTarget.value;
      console.log(`Showing ${window.showPlotsForMeasurement} plots`);
      fillPlotsTable();
    });

    fillInteropTable(result, log_dir);
    fillMeasurementTable(result, log_dir);
    fillPlotsTable();

    $("#client").add("#server").add("#test").empty();
    $("#client").append(
      result.clients.map((e) =>
        makeButton(
          "client",
          e,
          undefined,
          result.images ? result.images[e].compliant : undefined
        )
      )
    );
    $("#server").append(
      result.servers.map((e) =>
        makeButton(
          "server",
          e,
          undefined,
          result.images ? result.images[e].compliant : undefined
        )
      )
    );
    $("#test").append(
      Object.keys(result.tests).map((e) =>
        makeButton(
          "test",
          e,
          makeTooltip(
            result.tests[e].name,
            result.tests[e].desc,
            result.tests[e].timeout
          )
        )
      )
    );
    setButtonState();

    $("table.result").delegate("td", "mouseover mouseleave", function (e) {
      const t = $(this).closest("table.result");
      if (e.type === "mouseover") {
        $(this).parent().addClass("hover-xy");
        t.children("colgroup").eq($(this).index()).addClass("hover-xy");
        t.find("th").eq($(this).index()).addClass("hover-xy");
        t.find(".eff-row th").eq($(this).index()).addClass("hover-xy");
      } else {
        $(this).parent().removeClass("hover-xy");
        t.children("colgroup").eq($(this).index()).removeClass("hover-xy");
        t.find("th").eq($(this).index()).removeClass("hover-xy");
        t.find(".eff-row th").eq($(this).index()).removeClass("hover-xy");
      }
    });
  }

  function load(dir) {
    document.getElementsByTagName("body")[0].classList.add("loading");
    var xhr = new XMLHttpRequest();
    xhr.responseType = "json";
    xhr.open("GET", `${LOGS_BASE_URL}logs/${dir}/result.json`);
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== XMLHttpRequest.DONE) return;
      if (xhr.status !== 200) {
        console.log("Received status: ", xhr.status);
        return;
      }
      process(xhr.response, dir);
      document.getElementsByTagName("body")[0].classList.remove("loading");
    };
    xhr.send();
  }

  load("latest");

  // enable loading of old runs
  var xhr = new XMLHttpRequest();
  xhr.responseType = "json";
  xhr.open("GET", `${LOGS_BASE_URL}logs/logs.json`);
  xhr.onreadystatechange = function () {
    if (xhr.readyState !== XMLHttpRequest.DONE) return;
    if (xhr.status !== 200) {
      console.log("Received status: ", xhr.status);
      return;
    }
    var s = document.createElement("select");
    s.className = "custom-select custom-select-sm";
    xhr.response.reverse().forEach(function (el) {
      var opt = document.createElement("option");
      opt.innerHTML = el.replace("logs_", "");
      opt.value = el;
      s.appendChild(opt);
    });
    s.addEventListener("change", function (ev) {
      load(ev.currentTarget.value);
    });
    document.getElementById("available-runs").appendChild(s);
    load(s.value);
  };
  xhr.send();
})();
