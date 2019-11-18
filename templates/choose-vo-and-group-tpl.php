<?php

/**
 * This is simple example of template where user can choose where they want to register to access the requested service
 *
 * Allow type hinting in IDE
 * @var SimpleSAML_XHTML_Template $this
 * @var sspmod_perun_model_Group[] $groups;
 * @var sspmod_perun_model_Vo $vo
 */

$this->data['head'] = '<link rel="stylesheet" media="screen" type="text/css" href="' . SimpleSAML_Module::getModuleUrl('perun/res/css/perun_identity_choose_vo_and_group.css')  . '" />';

$vos = $this->data['vos'];
$groups = $this->data['groups'];
$registerUrlBase = $this->data['registerUrlBase'];
$spMetadata = $this->data['SPMetadata'];
$stateId = $this->data['stateId'];
$serviceName = '';
$informationURL = '';

if ($spMetadata['name']['en']) {
	$serviceName = $spMetadata['name']['en'];
}

if ($spMetadata['InformationURL']['en']) {
	$informationURL = $spMetadata['InformationURL']['en'];
}

$this->data['header'] = "";

$this->includeAtTemplateBase('includes/header.php');

if (isset($_POST['selectedGroup'])) {
	$params = array();
	$vo = explode(':', $_POST['selectedGroup'],2)[0];
    $group = explode(':', $_POST['selectedGroup'],2)[1];
	$callback = SimpleSAML_Module::getModuleURL('perun/perun_identity_callback.php', array('stateId' => $stateId));

	$params['vo'] = $vo;

	if ($group !== "members") {
		$params['group'] = $group;
	}

	$params[sspmod_perun_Auth_Process_PerunIdentity::TARGET_NEW] = $callback;
	$params[sspmod_perun_Auth_Process_PerunIdentity::TARGET_EXISTING] = $callback;
	$params[sspmod_perun_Auth_Process_PerunIdentity::TARGET_EXTENDED] = $callback;
	\SimpleSAML\Utils\HTTP::redirectTrustedURL($registerUrlBase, $params);
}

$header = $this->t('{perun:perun:choose-vo-and-group-tpl_header-part1}');
if (!empty($serviceName) && !empty($informationURL)) {
	$header .= '<a href="' . $informationURL . '">' . $serviceName . '</a>';
} elseif (!empty($serviceName)) {
	$header .=  $serviceName;
}
$header .= $this->t('{perun:perun:choose-vo-and-group-tpl_header-part2}');

echo '<div id="head">';
echo '<h1>' . $header. '</h1>';
echo '</div>';

echo '<div class="msg">' . $this->t('{perun:perun:choose-vo-and-group-tpl_message}'). '</div>';

?>

    <div class="list-group">

        <form action="" method="post">
            <h4> <?php echo $this->t('{perun:perun:choose-vo-and-group-tpl_select-vo}');  ?> </h4>
            <select id="selectVo" class="form-control" name="selectedVo" onchange="filter()" required>
            <?php
            foreach ($vos as $key => $vo) {
                echo '<option  value="' . $key .'" >' . $vo->getName() . '</option>';
            }
            ?>
            </select>

            <h4 class="selectGroup" style="display: none"><?php echo $this->t('{perun:perun:choose-vo-and-group-tpl_select-group}');  ?></h4>
            <select  class="selectGroup form-control" name="selectedGroup" class="form-control" style="display: none" required>
                <?php
                foreach ($groups as $group) {
                    echo '<option class="groupOption" value="' . $group->getUniqueName() .'" >' . $group->getDescription() . '</option>';
                }
                ?>
            </select>

            <input type="submit" value="<?php echo $this->t('{perun:perun:choose-vo-and-group-tpl_continue}');  ?>" class="btn btn-lg btn-primary btn-block">
        </form>
    </div>

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <script type="text/javascript">
        function filter() {
            hideGroups();
            $('.selectGroup').val("");
            var vo = $("#selectVo").val();
            if (vo !== "") {
                showGroups();
                $(".groupOption").each(function () {
                    var value = $(this).val();
                    if (value.startsWith(vo,0)) {
                        $(this).show();
                    } else {
                        $(this).hide();
                    }
                })
            }
        }

        function showGroups() {
            $(".selectGroup").show();
        }

        function hideGroups() {
            $(".selectGroup").hide();
        }

        $(document).ready($("#selectVo").val(""));
    </script>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>