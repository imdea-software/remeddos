(function($) {

	"use strict";

	$('js-datetimepicker').datetimepicker({
		allowInputToggle: true,
		showClose: true,
		showClear: true,
		showTodayButton: true,
		format: "MM/DD/YYYY",
		icons: {
			  time:'fa fa-clock-o',
	
			  down:'fa fa-chevron-down',
	
			  previous:'fa fa-chevron-left',
	
			  next:'fa fa-chevron-right',
	
			  today:'fa fa-chevron-up',
	
			  clear:'fa fa-trash',
	
			  close:'fa fa-close'
			},
	
		});
})(jQuery);
