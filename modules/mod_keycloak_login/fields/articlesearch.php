<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Form\Field\TextField;
use Joomla\CMS\Uri\Uri;

final class JFormFieldArticlesearch extends TextField
{
    protected $type = 'Articlesearch';

    protected function getInput()
    {
        $id = (string) ($this->id ?? '');
        $name = (string) ($this->name ?? '');
        $value = (int) ($this->value ?? 0);

        $db = Factory::getDbo();
        $title = '';
        if ($value > 0) {
            try {
                $query = $db->getQuery(true)
                    ->select($db->quoteName('title'))
                    ->from($db->quoteName('#__content'))
                    ->where($db->quoteName('id') . ' = ' . (int) $value);
                $db->setQuery($query);
                $title = (string) $db->loadResult();
            } catch (\Throwable $e) {
                $title = '';
            }
        }

        $base = rtrim((string) Uri::root(), '/');
        $ajaxUrl = $base . '/index.php?option=com_ajax&module=keycloak_login&method=searchArticles&format=json';

        $inputId = $id . '_search';
        $listId = $id . '_results';
        $hiddenId = $id;

        $titleEsc = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');

        $document = Factory::getApplication()->getDocument();
        $wa = $document->getWebAssetManager();

        $script = '';
        $script .= '(function(){';
        $script .= 'function init(){';
        $script .= 'var input=document.getElementById(' . json_encode($inputId) . ');';
        $script .= 'var hidden=document.getElementById(' . json_encode($hiddenId) . ');';
        $script .= 'var list=document.getElementById(' . json_encode($listId) . ');';
        $script .= 'if(!input||!hidden||!list){return;}';
        $script .= 'var ajaxUrl=' . json_encode($ajaxUrl) . ';';
        $script .= 'var timer=null;';
        $script .= 'function clearList(){list.innerHTML="";list.style.display="none";}';
        $script .= 'function setItems(items){list.innerHTML="";';
        $script .= 'if(!items||!items.length){clearList();return;}';
        $script .= 'items.slice(0,5).forEach(function(it){';
        $script .= 'var a=document.createElement("a");a.href="#";a.className="list-group-item list-group-item-action";a.textContent=it.title;';
        $script .= 'a.addEventListener("click",function(ev){ev.preventDefault();hidden.value=it.id;input.value=it.title;clearList();});';
        $script .= 'list.appendChild(a);});';
        $script .= 'list.style.display="block";';
        $script .= '}';
        $script .= 'function search(){var term=(input.value||"").trim();';
        $script .= 'if(term.length<2){clearList();return;}';
        $script .= 'fetch(ajaxUrl+"&term="+encodeURIComponent(term),{credentials:"same-origin"})';
        $script .= '.then(function(r){return r.json();})';
        $script .= '.then(function(data){';
        $script .= 'var items=[];';
        $script .= 'if(data && data.items){items=data.items;}';
        $script .= 'else if(data && data.data && data.data.items){items=data.data.items;}';
        $script .= 'setItems(items);';
        $script .= '})';
        $script .= '.catch(function(){clearList();});';
        $script .= '}';
        $script .= 'input.addEventListener("input",function(){hidden.value="0";if(timer){clearTimeout(timer);}timer=setTimeout(search,250);});';
        $script .= 'document.addEventListener("click",function(ev){if(!list.contains(ev.target) && ev.target!==input){clearList();}});';
        $script .= '}';
        $script .= 'if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",init);}else{init();}';
        $script .= '})();';

        $wa->addInlineScript($script);

        $html = '';
        $html .= '<input type="hidden" id="' . htmlspecialchars($hiddenId, ENT_QUOTES, 'UTF-8') . '" name="' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '" value="' . (int) $value . '">';
        $html .= '<input type="text" class="form-control" id="' . htmlspecialchars($inputId, ENT_QUOTES, 'UTF-8') . '" value="' . $titleEsc . '" placeholder="Search..." autocomplete="off">';
        $html .= '<div class="list-group mt-2" id="' . htmlspecialchars($listId, ENT_QUOTES, 'UTF-8') . '" style="display:none;"></div>';

        return $html;
    }
}
