// create a checkbox function to disable buttons unless they are enabled
$(document).ready(() => {
    $("#dangerCheckbox").change(function () {
        $(".dangerous").attr("disabled", !this.checked);
    });
    $('#csrFileInput').on("change", function () {
        $('#saveCsr').prop('disabled', !$(this).val());
    });
});
