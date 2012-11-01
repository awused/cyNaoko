google.load('visualization', '1', {'packages':['corechart', 'annotatedtimeline']});
$('body').ready(function(){

popularVideoTable = $('#popular_video_table tbody')
for (i = 0; i < popularVideos.length; i++){
    row = $('<tr><td class="video"></td><td class="freq"></td></tr>');
    switch (popularVideos[i][0]){
        case "yt":
            link = "http://youtube.com/watch?v=" + popularVideos[i][1];
            break;
        case "vm":
            link = "http://vimeo.com/" + popularVideos[i][1];
            break;
        case "sc":
            // Special case. Will have to use soundcloud's api from python to find the track url. TODO later
            link = "#"
            break;
        case "bt":
            link = "http://blip.tv/posts/" + popularVideos[i][1];
            break;
        case "dm":
            link = "http://www.dailymotion.com/video/" + popularVideos[i][1];
            break;
        default:
            link = "#";
    }
    row.children('.video').append($("<a></a>", {
            text : popularVideos[i][2],
            href :link,
        }));
    row.children('.freq').text(popularVideos[i][4]);
    popularVideoTable.append(row);  
}});

google.setOnLoadCallback(function(){
var userVideoData = new google.visualization.DataTable();
userVideoData.addColumn('string', 'Topping');
userVideoData.addColumn('number', 'Slices');
userVideoData.addRows(userVideoStats);
var userVideoChart = new google.visualization.PieChart(document.getElementById('user_video_div'));
userVideoChart.draw(userVideoData, {width: "100%", height: "100%"});


var userChatData = new google.visualization.DataTable();
userChatData.addColumn('string', 'Topping');
userChatData.addColumn('number', 'Slices');
userChatData.addRows(userChatStats);
var userChatChart = new google.visualization.PieChart(document.getElementById('user_chat_div'));
userChatChart.draw(userChatData, {width: "100%", height: "100%"});


var averageUserData = new google.visualization.DataTable();
averageUserData.addColumn('datetime', 'Time'); 
averageUserData.addColumn('number', 'Short Moving average');
averageUserData.addColumn('number', 'Long Moving average');
averageUserData.addColumn('number', 'Number of Users');
var smaspan = 12*7;
var lmaspan = 4*7*30;
for(i=0; i<averageUsers.length;i++) {
    var row;
    averageUsers[i][0] = new Date(averageUsers[i][0]); 
    row = [averageUsers[i][0], 0, 0, averageUsers[i][1]]
    if(i > (smaspan-1)) {
        var sum = averageUsers.slice(i-smaspan, i).reduce(function(prev, cur) {return prev + cur[1]}, 0);
        //console.log(sum);
        row[1] = sum/smaspan;
    }
    if(i > (lmaspan-1)) {
        var sum = averageUsers.slice(i-lmaspan, i).reduce(function(prev, cur) {return prev + cur[1]}, 0);
        //console.log(sum);
        row[2] = sum/lmaspan;
    }
    averageUserData.addRow(row);
}
var averageUserTimeline = new google.visualization.AnnotatedTimeLine(document.getElementById('average_user_div'));
averageUserTimeline.draw(averageUserData, {width: "800px", height : "800px", 'displayAnnotations': true, /*zoomStartTime : new Date(2011, 8, 8), zoomEndTime : new Date(),*/ colors:['black', 'green', 'cyan'], max: 50});
});
