/**
 *   I don't recommend using this plugin on large tables, I just wrote it to make the demo useable. It will work fine for smaller tables
 *   but will likely encounter performance issues on larger tables.
 *
 *		<input type="text" class="form-control" id="dev-table-filter" data-action="filter" data-filters="#dev-table" placeholder="Filter Developers" />
 *		$(input-element).filterTable()
 *
 *	The important attributes are 'data-action="filter"' and 'data-filters="#table-selector"'
 */
 (function () {
  "use strict";
  var $ = jQuery;
  $.fn.extend({
    filterTable: function () {
      return this.each(function () {
        $(this).on("keyup", function (e) {
          $(".filterTable_no_results").remove();
          var $this = $(this),
            search = $this.val().toLowerCase(),
            target = $this.attr("data-filters"),
            $target = $(target),
            $rows = $target.find("tbody tr");

          if (search == "") {
            $rows.show();
          } else {
            $rows.each(function () {
              var $this = $(this);
              $this.text().toLowerCase().indexOf(search) === -1
                ? $this.hide()
                : $this.show();
            });
            if ($target.find("tbody tr:visible").size() === 0) {
              var col_count = $target.find("tr").first().find("td").size();
              var no_results = $(
                '<tr class="filterTable_no_results"><td colspan="' +
                  col_count +
                  '">No results found</td></tr>'
              );
              $target.find("tbody").append(no_results);
            }
          }
        });
      });
    }
  });
  $('[data-action="filter"]').filterTable();
})(jQuery);

$(function () {
  // attach table filter plugin to inputs
  $('[data-action="filter"]').filterTable();

  $(".container").on("click", ".panel-heading span.filter", function (e) {
    var $this = $(this),
      $panel = $this.parents(".panel");

    $panel.find(".panel-body").slideToggle();
    if ($this.css("display") != "none") {
      $panel.find(".panel-body input").focus();
    }
  });
  // $('[data-toggle="tooltip"]').tooltip();
});







const okay_keys = ["name", "regex"];
const baseUrl = 'http://10.10.1.86:1337/cos/';
const maxRequests = 334;

async function fetchData(url) {
  return new Promise((resolve, reject) => {
      $.ajax({
          type: "GET",
          url: url,
          dataType: "json",
          success: resolve,
          error: reject
      });
  });
}

async function fetchAndProcessAllData() {
  const dataPromises = [];

  for (let i = 1; i <= maxRequests; i++) {
      const url = baseUrl + i;
      dataPromises.push(fetchData(url));
  }

  try {
      const dataArray = await Promise.all(dataPromises);
      processAndDisplayData(dataArray);
  } catch (error) {
      console.error("Error fetching or processing data:", error);
  }
}

function processAndDisplayData(dataArray) {
  const tableBody = document.getElementById("data-table-body");

  for (let i = 0; i < dataArray.length; i++) {
      const obj = dataArray[i];
      const row = document.createElement("tr");

      const cell = document.createElement("td");
      cell.textContent = i;
      row.appendChild(cell);

      for (const key in obj) {
          const value = obj[key];
          if (okay_keys.includes(key)) {
              const cell = document.createElement("td");
              cell.textContent = value;
              row.appendChild(cell);
          }
      }

      tableBody.appendChild(row);
  }
}

$(document).ready(() => {
  fetchAndProcessAllData();
});
