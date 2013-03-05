function sanitize(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/["']/g, '&quot;');
}
function sanitizeMedia(m) {
    for(field in m) {
        if(typeof(m[field]) === 'string') {
            val = m[field]
            console.log("Sanitizing %s", val);
            m[field] = sanitize(val);
        }
    }        
}

Media.create = _.wrap(Media.create, function() {
    fn = arguments[0];
    J  = arguments[1];
    sanitizeMedia(J);
    return fn.apply(Media, _.rest(arguments));
});
