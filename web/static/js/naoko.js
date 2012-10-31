google.load('visualization', '1', {'packages':['corechart', 'annotatedtimeline']});
google.setOnLoadCallback(function(){

var userVideoData = new google.visualization.DataTable();
userVideoData.addColumn('string', 'Topping');
userVideoData.addColumn('number', 'Slices');
userVideoData.addRows(userVideoStats);
var userVideoChart = new google.visualization.PieChart(document.getElementById('user_video_div'));
userVideoChart.draw(userVideoData/*, {width: 800, height: 480}*/);


var userChatData = new google.visualization.DataTable();
userChatData.addColumn('string', 'Topping');
userChatData.addColumn('number', 'Slices');
userChatData.addRows(userChatStats);
var userChatChart = new google.visualization.PieChart(document.getElementById('user_chat_div'));
userChatChart.draw(userChatData/*, {width: 800, height: 480}*/);
/*
var dat = new google.visualization.DataTable();
dat.addColumn('datetime', 'Time'); 
dat.addColumn('number', 'Short Moving average');
dat.addColumn('number', 'Long Moving average');
dat.addColumn('number', 'Number of Users');
var smaspan = 12*7;
var lmaspan = 4*7*30;
for(i=0; i<info.length;i++) {
    var row;
    info[i][0] = new Date(info[i][0]); 
    row = [info[i][0], 0, 0, info[i][1]]
    if(i > (smaspan-1)) {
        var sum = info.slice(i-smaspan, i).reduce(function(prev, cur) {return prev + cur[1]}, 0);
        console.log(sum);
        row[1] = sum/smaspan;
    }
    if(i > (lmaspan-1)) {
        var sum = info.slice(i-lmaspan, i).reduce(function(prev, cur) {return prev + cur[1]}, 0);
        console.log(sum);
        row[2] = sum/lmaspan;
    }
    dat.addRow(row);
}
var annotatedtimeline = new google.visualization.AnnotatedTimeLine(document.getElementById('info_div'));
annotatedtimeline.draw(dat, {width: 800, height : 800, 'displayAnnotations': true, zoomStartTime : new Date(2011, 8, 8), zoomEndTime : new Date(), colors:['black', 'green', 'cyan'], max: 50});*/
});
