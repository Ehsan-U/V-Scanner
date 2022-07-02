$(document).ready(function (){
    $("#grade_div").fadeIn("slow");
    $("[data-toggle='tooltip']").tooltip({animation:true});
})


//  validate input url
function validate() {
    console.log('validation')
    main_element = document.getElementById("url");
    url_div = document.getElementById("url_div")
    if (main_element.value.length < 12) {
          $(main_element).effect( "shake",{times:2,distance:8},600);
          main_element.focus()
          // stop loader when invalid input
          return false
    }
    else {
        console.log('validation regex')
        element = document.getElementById("url").value.toLowerCase();
        regex = new RegExp("http://\\w.*\\.\\w.*|https://\\w.*\\.\\w.*",)
        if (regex.test(element) === false) {
            $(main_element).effect( "shake",{times:2,distance:8},600);
            main_element.focus()
            // stop loader when invalid input
            return false
        }
        else {
            // continue loader when valid input
            return true
        }
    }
}

function send_req() {
    valid = validate()
    if (valid) {
        loader()
        const csrftoken = Cookies.get('csrftoken');
        url = $('#url').val()
        selection = $('#selection').val()
        $.ajax({
            'type':'POST',
            'url':'http://127.0.0.1:8000/result/',
            'data':{'search':url,'selection':selection,'csrfmiddlewaretoken':csrftoken},
            success:function(response) {
                loader(true) 
                window.location = `http://127.0.0.1:8000/result/?target=${url}`
            }
            
        })
    }
    else {
        //pass
    }
}

// make cookie red if not secure
function missing_cookie()
{
    console.log("cookies")
    try
    {
        // alert("KO")
        table = document.getElementById("raw_t");
        rows = table.getElementsByTagName("tr");
        for (tr=0;tr<rows.length;tr++) {
            if (rows[tr].getElementsByTagName("th")[0].innerText.toLowerCase() === "Set-Cookie".toLowerCase()) {
                cookie = rows[tr].getElementsByTagName("td")[0].innerText.toLowerCase()
                if (cookie.match("httponly") || cookie.match("samesite") || cookie.match("secure")) {
                    // pass
                }
                else {
                    rows[tr].getElementsByTagName("th")[0].style.color = "red";
                }
            }
        }
    }
    catch (err)
    {
        alert(err);
    }
}

// loader animation
function loader(stop=false) {
    console.log("loader")
    if (stop == true) {
        var element = document.getElementById("scan");
        element.innerHTML = 'Scan';
    }
    else {
        var element = document.getElementById("scan");
        element.innerHTML = '<span class=\"spinner-border spinner-border-sm\"></span> Scanning';
    }
}

// be_responsive()
// window.addEventListener('resize',be_responsive)
//
// function be_responsive() {
//     console.log("resize")
//     width = document.documentElement.clientWidth
//     form = document.getElementById('scan_form')
//     if (width < 440) {
//         check = true
//         form.className = "d-inline-block"
//         form.innerHTML =
//             `
//             <div class="pe-2">
//               <input name="search" type="text" class="form-control" maxlength="100" minlength="" id="url" placeholder="Enter website URL">
//             </div>
//             <div class="form-check-inline mt-2">
//                 <div class="pe-2">
//                   <select class="form-select" id="selection" name="selection">
//                       <option value="default" selected="">Light</option>
//                       <option value="deep">Deep</option>
//                   </select>
//                 </div>
//                 <div>
//                     <button id="scan" class="btn btn-primary" value="submit">Scan</button>
//                 </div>
//             </div>
//             `
//     }
//     else if (width > 440) {
//         form.className = "form-check-inline"
//         form.innerHTML =
//             `
//             <div class="pe-2">
//               <input name="search" type="text" class="form-control" maxlength="100" minlength="" id="url" placeholder="Enter website URL">
//             </div>
//             <div class="pe-2">
//               <select class="form-select" id="selection" name="selection">
//                   <option value="default" selected="">Light</option>
//                   <option value="deep">Deep</option>
//               </select>
//             </div>
//             <div>
//                 <button id="scan" class="btn btn-primary" value="submit">Scan</button>
//             </div>
//             `
//     }
// }

if (window.location.href.match('result')){
    responsive_grades()
    window.addEventListener('resize',responsive_grades)
}


function responsive_grades() {
    console.log("grades")
    width = document.documentElement.clientWidth
    grades = document.getElementById('grades_display')
    sections = document.querySelectorAll("[id='sect']")
    if (width < 576) {
        grades.className = 'mt-3 mb-3'
        for (var i=0;i<sections.length;i++) {
            sections[i].className = 'pt-5 pb-5'
        }
    }
    else if (width > 576) {
        grades.className = 'container my-5'
        for (var i=0;i<sections.length;i++) {
            sections[i].className = 'ms-2 me-2 pt-5 pb-5'
        }
    }
}

viewer = Django_Class()
