var nodegit = require("nodegit");
var promisify = require("promisify-node");
var fse = promisify(require("fs-extra"));
var request = promisify(require("request"));
var path =require("path");
var repoPath = "/tmp/ ";
var express =   require("express");
var url = require("url");
var app  =   express();
var bodyParser  =   require("body-parser");
var router  =   express.Router();
var repoRoot = "http://ec2-54-152-38-69.compute-1.amazonaws.com/";
var repoName = "root/";
var private_token = "JtjTzjkku3npH3tMRnx4";
var logger = require('tracer').colorConsole();
var repository;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({"extended" : false}));

router.route("/sync/init").post(function (req,res) {
  var name = req.body.name;

  if(!name){
    res.status(500).json({error :"Invalid repository name"});
  }

  else{
    var repoPath = path.join("/tmp",name);
    var repoName = repoRoot + "root/"+name+".git";
    logger.log(repoName)
    logger.log(repoPath)
    fse.remove(repoPath).then(function() {
      nodegit.Clone(repoName,repoPath).then(function(repo) {
          return repo;
        }).then(function(repo) {
          var hook = url.format({
            protocol: req.protocol,
            host: req.get('host'),
            pathname: "sync/hook"
          });
          logger.log(hook);
          logger.log(repoRoot+encodeURIComponent(repoName)+"/hooks");
          var options = {
            url:repoRoot+"api/v3/projects/"+encodeURIComponent("root/"+name)+"/hooks",
            method:'POST',
            qs : {
             "private_token" : private_token,
             "url":hook
           }
         }
         request(options,function(err,res){
          if(err){
            logger.log(err);
          }
        });
       }).catch(function (err) {
        logger.log(err);
        res.status(500).json({error :"Something went wrong!"});
      });
     });  
  }


});

router.route("/sync/hook").post(function(req,res){

  var name = req.body.project.name;
  var repoPath = path.join("/tmp",name);
  // Open a repository that needs to be fetched and fast-forwarded
  nodegit.Repository.open(path.resolve(__dirname,repoPath))
  .then(function(repo) {
    repository = repo;
    logger.log(repository);
    return repository.fetchAll();
  })
    // Now that we're finished fetching, go ahead and merge our local branch
    // with the new one
    .then(function() {
      return repository.mergeBranches("master", "origin/master");
    })
    .catch(function(err) {
      logger.log(err);
    });
  });

router.route("/sync/restart").post(function(req,res){
  var name = req.body.name.trim();
  var repoPath = path.join("/tmp",name);
  // logger.log(path)
  // Open a repository that needs to be fetched and fast-forwarded
  nodegit.Repository.open(repoPath)
  .then(function(repo) {
    repository = repo;
    logger.log(repository);
    return repository.fetchAll();
  })
    // Now that we're finished fetching, go ahead and merge our local branch
    // with the new one
    .then(function() {
      return repository.mergeBranches("master", "origin/master");
    })
    .then(function () {
      var exec = require('child_process').exec;
      
      // logger.log(path+name)
      var execFile = require('child_process').execFile;
      execFile("/home/ubuntu/libgit2-0.24.1/IncrementalCheckpointing/myrestart",[repoPath], function(error, stdout, stderr) {
        logger.log(stdout)
        if(error)
          logger.log(error)
      });

    })
    .catch(function(err) {
      logger.log(err);
    });

});
app.use('/',router);

app.listen(3000); 
logger.log("Listening to PORT 3000");